"""Explicit additive migration and local administrator bootstrap commands."""

import argparse
from getpass import getpass
import os
from pathlib import Path
import secrets

from sqlalchemy import inspect, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.schema import CreateColumn
from pydantic import ValidationError

from backend.auth import hash_password
from backend.config import settings
from backend.database import Base, create_database_engine, init_db, sessions_for
from backend.models import BootstrapState, User
from backend.schemas import UserRegister


def write_config(path, database_url):
    from backend.config import Settings
    config = Settings(DATABASE_URL=database_url, SECRET_KEY=secrets.token_urlsafe(48),
                      SENSOR_API_TOKEN=secrets.token_urlsafe(48)).validate()
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "w") as output:
        output.write(f"DATABASE_URL={database_url}\nSECRET_KEY={config.SECRET_KEY}\n"
                     f"SENSOR_API_TOKEN={config.SENSOR_API_TOKEN}\nSENSOR_ID=sensor-local\nCORS_ORIGINS=\n")


def migrate(engine):
    """Add nullable provenance columns and new tables without rewriting old rows."""
    import backend.models  # Register every current table before schema inspection.
    if engine.dialect.name not in ("sqlite", "postgresql"):
        raise ValueError("Only SQLite and PostgreSQL migrations are supported")
    with engine.begin() as connection:
        inspector = inspect(connection)
        for table in Base.metadata.sorted_tables:
            if not inspector.has_table(table.name):
                table.create(connection)
                continue
            present = {column["name"] for column in inspector.get_columns(table.name)}
            for column in table.columns:
                if column.name in present:
                    continue
                if not column.nullable or column.primary_key:
                    raise RuntimeError(f"Cannot automatically add required column {table.name}.{column.name}")
                definition = str(CreateColumn(column).compile(dialect=engine.dialect))
                table_name = connection.dialect.identifier_preparer.quote(table.name)
                connection.exec_driver_sql(f"ALTER TABLE {table_name} ADD COLUMN {definition}")
            for index in table.indexes:
                index.create(connection, checkfirst=True)
    init_db(engine)


def bootstrap_admin(engine, username, email, password):
    user_in = UserRegister(username=username, email=email, password=password, is_admin=True)
    with sessions_for(engine)() as db:
        if db.query(User).first() is not None:
            raise ValueError("Bootstrap requires an empty user table; use an existing administrator")
        try:
            # A singleton insert serializes competing local bootstrap attempts.
            db.add(BootstrapState(id=1))
            db.flush()
            user = User(username=user_in.username, email=str(user_in.email),
                        hashed_password=hash_password(user_in.password), is_admin=True)
            db.add(user)
            db.commit()
            return user.id
        except IntegrityError as exc:
            db.rollback()
            raise ValueError("Administrator bootstrap has already completed") from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    configure = sub.add_parser("init-config", help="Generate private local configuration; never overwrite an existing file")
    configure.add_argument("--output", type=Path, default=Path("backend/.env"))
    configure.add_argument("--database-url", required=True)
    sensor_config = sub.add_parser("export-sensor-config", help="Write only sensor credentials to a private new file")
    sensor_config.add_argument("--output", type=Path, default=Path("runtime/sensor.env"))
    sub.add_parser("migrate", help="Back up the configured database before applying additive migration")
    admin = sub.add_parser("create-admin")
    admin.add_argument("--username", required=True)
    admin.add_argument("--email", required=True)
    args = parser.parse_args()
    if args.command == "init-config":
        write_config(args.output, args.database_url)
        print(f"Private configuration written to {args.output}; no secrets printed")
        return
    settings.validate()
    if args.command == "export-sensor-config":
        args.output.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(args.output, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "w") as output:
            output.write(f"SENSOR_API_TOKEN={settings.SENSOR_API_TOKEN}\nSENSOR_ID={settings.SENSOR_ID}\n")
        print(f"Sensor-only configuration written to {args.output}; no secrets printed")
        return
    engine = create_database_engine(settings.DATABASE_URL)
    try:
        if args.command == "migrate":
            migrate(engine)
            print("Configured database schema is current; existing rows preserved")
        else:
            init_db(engine)
            password = getpass("New administrator password: ")
            if password != getpass("Confirm password: "):
                parser.error("Passwords differ")
            bootstrap_admin(engine, args.username, args.email, password)
            print("Administrator created")
    except ValidationError:
        parser.error("Invalid account details or password policy; password values are not printed")
    except ValueError as exc:
        parser.error(str(exc))
    finally:
        engine.dispose()


if __name__ == "__main__":
    main()
