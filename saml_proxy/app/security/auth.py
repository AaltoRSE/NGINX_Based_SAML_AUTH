from starlette.middleware.authentication import AuthenticationMiddleware
from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    AuthenticationError,
    SimpleUser,
    BaseUser,
)
from starlette.middleware import Middleware
from security.session import SessionHandler
from fastapi import HTTPException, status


class SAMLUser(SimpleUser):
    def __init__(self, username: str, userdata: dict):
        self.username = username
        self.data = userdata

    def get_user_data(self):
        return self.data


class SAMLSessionBackend(AuthenticationBackend):
    def __init__(self, session_handler: SessionHandler):
        self.session_handler = session_handler

    async def authenticate(self, conn):
        try:
            if conn.session == None:
                return
        except AssertionError:
            return

        # check for authentication:
        if not "key" in conn.session:
            return
        try:
            data = self.session_handler.get_session_data(conn.session["key"])
            if data == None:
                # This is not a valid session any more... so we need to reset it somehow.
                clean_session(conn.session)
                return
        except HTTPException:
            return
        return AuthCredentials(["authenticated"]), SAMLUser(data["samlNameId"], data)


def clean_session(session):
    session.pop("key")
    session["invalid"] = True
