import os

from dotenv import load_dotenv
from pymongo import MongoClient
from pymongo.errors import OperationFailure, PyMongoError

def main() -> None:
    load_dotenv()

    connection_string = os.getenv("mongodb_uri")
    if not connection_string:
        raise RuntimeError("mongodb_uri is not set in the .env file")

    client = MongoClient(connection_string, serverSelectionTimeoutMS=5000)
    try:
        client.admin.command("ping")
        print("Successfully connected to MongoDB.")
    except OperationFailure as exc:
        if exc.code == 8000 or "Authentication failed" in str(exc):
            raise RuntimeError(
                "MongoDB authentication failed. Check the Atlas database username, "
                "password, and URL-encode special characters in the password."
            ) from exc
        raise RuntimeError("MongoDB rejected the connection request.") from exc
    except PyMongoError as exc:
        raise RuntimeError(f"Could not connect to MongoDB: {exc}") from exc
    finally:
        client.close()


if __name__ == "__main__":
    main()
