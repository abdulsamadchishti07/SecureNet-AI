"""User and sensor authentication with independent credentials and explicit roles."""

from datetime import datetime, timedelta, timezone
import secrets

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


def decode_token(token, configuration=None):
    config = configuration or settings
    try:
        claims = jwt.decode(token, config.SECRET_KEY, algorithms=["HS256"],
                            issuer="securenet-ai", audience="securenet-dashboard",
                            options={"require": ["exp", "iat", "sub", "type"]})
        if claims["type"] != "access" or not claims["sub"].isdigit():
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
