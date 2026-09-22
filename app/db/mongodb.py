from pymongo import MongoClient

from app.core.config import settings

client: MongoClient | None = None
database = None


def connect_to_mongo() -> None:
    global client, database
    if client is not None and database is not None:
        return
    client = MongoClient(settings.mongodb_uri.get_secret_value())
    database = client[settings.mongodb_database]
    try:
        client.admin.command("ping")
        database.users.create_index("email", unique=True)
        database.scan_records.create_index([("user_id", 1), ("created_at", -1)])
        database.password_reset_tokens.create_index("expires_at", expireAfterSeconds=0)
        database.otp_records.create_index("email", unique=True)
        database.otp_records.create_index("expires_at", expireAfterSeconds=0)
    except Exception:
        client.close()
        client = None
        database = None
        raise


def close_mongo() -> None:
    global client, database
    if client is not None:
        client.close()
    client = None
    database = None


def get_database():
    if database is None:
        raise RuntimeError("MongoDB has not been initialized")
    return database
