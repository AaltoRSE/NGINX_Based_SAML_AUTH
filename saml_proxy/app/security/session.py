import os
import urllib
import pymongo
import secrets
import string
from datetime import datetime, timedelta
from fastapi import HTTPException, status, Security

import logging


class SessionHandler:
    def __init__(self, testing: bool = False, exp_time: int = 600):
        self.expire_time = exp_time
        if not testing:
            # Needs to be escaped if necessary
            mongo_user = urllib.parse.quote_plus(os.environ.get("MONGOUSER"))
            mongo_password = urllib.parse.quote_plus(os.environ.get("MONGOPASSWORD"))
            mongo_URL = os.environ.get("MONGOHOST")
            # Set up required endpoints.
            mongo_client = pymongo.MongoClient(
                "mongodb://%s:%s@%s/" % (mongo_user, mongo_password, mongo_URL)
            )
            self.setup(mongo_client)

    def setup(self, mongo_client: pymongo.MongoClient):
        self.db = mongo_client["sessions"]
        self.session_collection = self.db["sessions"]
        # Clean up sessions, we will not accept any session from a previous run
        self.session_collection.delete_many({})

    def create_session(
        self, session_data: dict, session_key: str = None, update_existing: bool = False
    ):
        if session_key == None:
            # Should be the case in most instances.
            session_key = self.generate_session_key()
        expires_delta = timedelta(seconds=self.expire_time)
        expire = datetime.now() + expires_delta
        dataToSet = {
            "key": session_key,
            "data": session_data,
            "expire": expire.timestamp(),
        }
        if update_existing:
            upsertCommand = {"$set": dataToSet}
        else:
            upsertCommand = {"$setOnInsert": dataToSet}
        result = self.session_collection.update_one(
            {"key": session_key}, upsertCommand, upsert=not update_existing
        )
        # Nothing should have happened, if something was matched.
        while (not update_existing) and (not result.matched_count == 0):
            # This should indicate, that the key already existed.
            if result.modified_count > 0:
                raise Exception(
                    "Updated an existing element while no update was requested"
                )
            session_key = self.generate_session_key()
            upsertCommand = {
                "$setOnInsert": {
                    "key": session_key,
                    "data": session_data,
                    "expire": expire,
                }
            }
            result = self.session_collection.update_one(
                {"key": session_key}, upsertCommand, upsert=True
            )
        return session_key

    def get_session_data(self, session_key):
        entry = self.session_collection.find_one({"key": session_key})
        if entry == None:
            return None
        ctime = datetime.now().timestamp()
        if ctime >= entry["expire"]:
            # This is expired, we can remove it...
            self.session_collection.delete_one({"key": session_key})
            return None
        return entry["data"]

    def generate_session_key(self, length: int = 128):
        """
        Function to generate an API key.

        Parameters:
        - length (int, optional): Length of the generated API key. Defaults to 64.

        Returns:
        - str: The generated API key.
        """
        alphabet = string.ascii_letters + string.digits
        api_key = "".join(secrets.choice(alphabet) for _ in range(length))
        return api_key

    def clear_session(self, session_key: str):
        self.session_collection.delete_one({"key": session_key})
