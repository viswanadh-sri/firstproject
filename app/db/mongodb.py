from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase

from app.core.config import settings

client: AsyncIOMotorClient | None = None
database: AsyncIOMotorDatabase | None = None


async def connect_to_mongo() -> None:
    global client, database
    client = AsyncIOMotorClient(settings.mongodb_uri.get_secret_value())
    database = client[settings.mongodb_database]
    await client.admin.command("ping")
    await database.users.create_index("email", unique=True)
    await database.password_reset_tokens.create_index("expires_at", expireAfterSeconds=0)


async def close_mongo() -> None:
    if client is not None:
        client.close()


def get_database() -> AsyncIOMotorDatabase:
    if database is None:
        raise RuntimeError("MongoDB has not been initialized")
    return database
