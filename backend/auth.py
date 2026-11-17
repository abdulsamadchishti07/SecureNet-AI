"""User and sensor authentication with independent credentials and explicit roles."""

from collections import OrderedDict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
import math
import secrets
from threading import Lock
import time

import bcrypt
import jwt
from fastapi import Depends, Header, HTTPException
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.orm import Session
from starlette.requests import HTTPConnection

from backend.config import settings
from backend.database import get_db
from backend.models import User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


def get_settings(connection: HTTPConnection):
    return connection.app.state.settings


def validate_password(password, *, new=False):
    if not isinstance(password, str):
        raise ValueError("Password must be text")
    if not 1 <= len(password.encode("utf-8")) <= 72 or (new and len(password) < 12):
        raise ValueError("New passwords need at least 12 characters and at most 72 UTF-8 bytes")
    return password


def hash_password(password):
    validate_password(password, new=True)
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password, hashed_password):
    try:
        validate_password(password)
        return bcrypt.checkpw(password.encode("utf-8"), hashed_password.encode("utf-8"))
    except (ValueError, TypeError, AttributeError):
        return False


def create_access_token(data, expires_delta=None, configuration=None):
    config = configuration or settings
    config.validate()
    now = datetime.now(timezone.utc)
    lifetime = expires_delta if expires_delta is not None else timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES)
    claims = {**data, "sub": str(data["sub"]), "exp": now + lifetime, "iat": now,
              "type": "access", "iss": "securenet-ai", "aud": "securenet-dashboard"}
    return jwt.encode(claims, config.SECRET_KEY, algorithm=config.ALGORITHM)


def create_refresh_token(data, expires_delta=None, configuration=None):
    config = configuration or settings
    config.validate()
    now = datetime.now(timezone.utc)
    lifetime = expires_delta if expires_delta is not None else timedelta(days=config.REFRESH_TOKEN_EXPIRE_DAYS)
    claims = {**data, "sub": str(data["sub"]), "jti": secrets.token_hex(16), "exp": now + lifetime,
              "iat": now, "type": "refresh", "iss": "securenet-ai", "aud": "securenet-dashboard"}
    return jwt.encode(claims, config.SECRET_KEY, algorithm=config.ALGORITHM)


def decode_token(token, configuration=None, token_type="access"):
    config = configuration or settings
    required = ["exp", "iat", "sub", "type", "jti"] if token_type == "refresh" else ["exp", "iat", "sub", "type"]
    try:
        claims = jwt.decode(token, config.SECRET_KEY, algorithms=["HS256"],
                            issuer="securenet-ai", audience="securenet-dashboard",
                            options={"require": required})
        if claims["type"] != token_type or not claims["sub"].isdigit():
            raise jwt.InvalidTokenError("Invalid token purpose or subject")
        return claims
    except (jwt.PyJWTError, ValueError, AttributeError) as exc:
        raise HTTPException(401, "Invalid or expired authentication token",
                            headers={"WWW-Authenticate": "Bearer"}) from exc


def resolve_user(token, db, config):
    if not token:
        raise HTTPException(401, "Authentication required", headers={"WWW-Authenticate": "Bearer"})
    user = db.get(User, int(decode_token(token, config)["sub"]))
    if user is None or not user.is_active:
        raise HTTPException(401, "User not found or deactivated")
    return user


def get_current_user(token=Depends(oauth2_scheme), db: Session = Depends(get_db),
                     config=Depends(get_settings)):
    return resolve_user(token, db, config)


def require_admin(user: User = Depends(get_current_user)):
    if not user.is_admin:
        raise HTTPException(403, "Administrator role required")
    return user


def require_sensor(x_sensor_token: str = Header(default=""), x_sensor_id: str = Header(default=""),
                   config=Depends(get_settings)):
    if (not secrets.compare_digest(x_sensor_token.encode(), config.SENSOR_API_TOKEN.encode())
            or x_sensor_id != config.SENSOR_ID):
        raise HTTPException(401, "Valid sensor credentials required")
    return config.SENSOR_ID


@dataclass
class _LoginBucket:
    failures: deque = field(default_factory=deque)
    pending: set = field(default_factory=set)


class LoginRateLimiter:
    """Bounded failure windows with atomic reservations for in-flight logins."""

    def __init__(self, max_attempts=5, ip_max_attempts=20, window_seconds=60.0,
                 max_keys=4096, clock=time.monotonic):
        self.max_attempts = max_attempts
        self.ip_max_attempts = ip_max_attempts
        self.window_seconds = float(window_seconds)
        self.max_keys = max_keys
        if (max_attempts < 1 or ip_max_attempts < 1 or max_keys < 2
                or not math.isfinite(self.window_seconds) or self.window_seconds <= 0):
            raise ValueError("Login limits must be positive, with room for at least two keys")
        self.clock = clock
        self._buckets = OrderedDict()
        self._lock = Lock()

    def _prune(self, key, now):
        bucket = self._buckets.get(key)
        if bucket is None:
            return None
        cutoff = now - self.window_seconds
        while bucket.failures and bucket.failures[0] <= cutoff:
            bucket.failures.popleft()
        if not bucket.failures and not bucket.pending:
            self._buckets.pop(key, None)
            return None
        return bucket

    def reserve(self, client_ip, username):
        """Return (reservation, retry_after); pending attempts consume both limits."""
        limits = (
            (("ip_user", client_ip, username), self.max_attempts),
            (("ip", client_ip), self.ip_max_attempts),
        )
        retry_after = 0
        with self._lock:
            now = self.clock()
            for key, limit in limits:
                bucket = self._prune(key, now)
                if bucket is None:
                    continue
                if len(bucket.failures) >= limit:
                    retry_after = max(retry_after, math.ceil(bucket.failures[0] + self.window_seconds - now), 1)
                elif len(bucket.failures) + len(bucket.pending) >= limit:
                    retry_after = max(retry_after, 1)
            if retry_after:
                return None, retry_after
            keys = tuple(key for key, _ in limits)
            missing = sum(key not in self._buckets for key in keys)
            if len(self._buckets) + missing > self.max_keys:
                for key in list(self._buckets):
                    self._prune(key, now)
                missing = sum(key not in self._buckets for key in keys)
                if len(self._buckets) + missing > self.max_keys:
                    # Keep live failures/reservations; eviction would reset quotas.
                    return None, 1
            token = object()
            for key in keys:
                bucket = self._buckets.setdefault(key, _LoginBucket())
                bucket.pending.add(token)
            return (token, keys), 0

    def complete(self, reservation, *, success):
        """Commit a credential failure, clear successful account failures, or cancel."""
        token, keys = reservation
        with self._lock:
            now = self.clock()
            for key in keys:
                bucket = self._buckets.get(key)
                if bucket is None or token not in bucket.pending:
                    continue
                bucket.pending.remove(token)
                if success is False:
                    bucket.failures.append(now)
                elif success is True and key[0] == "ip_user":
                    bucket.failures.clear()
                self._prune(key, now)
