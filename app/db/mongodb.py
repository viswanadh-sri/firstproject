from pymongo import MongoClient

from app.core.config import settings

client: MongoClient | None = None
database = None


def connect_to_mongo() -> None:
    global client, database
    client = MongoClient(settings.mongodb_uri.get_secret_value())
    database = client[settings.mongodb_database]
    client.admin.command("ping")
    database.users.create_index("email", unique=True)
    database.scan_records.create_index([("user_id", 1), ("created_at", -1)])
    database.password_reset_tokens.create_index("expires_at", expireAfterSeconds=0)
    database.otp_records.create_index("email", unique=True)
    database.otp_records.create_index("expires_at", expireAfterSeconds=0)


def close_mongo() -> None:
    if client is not None:
        client.close()


def get_database():
    if database is None:
        raise RuntimeError("MongoDB has not been initialized")
    return database
