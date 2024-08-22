from starlette.authentication import (
    AuthCredentials,
    AuthenticationBackend,
    SimpleUser,
)
from security.session import SessionHandler
from fastapi import HTTPException

# Adjust to your needs
allowed_users = ["test", "admin", "me@mydomain.com"]
group_field = "urn:oid:1.3.6.1.4.1.5923.1.1.1.1"
allowed_groups = ["employee"]


def authorize_user(saml_user_data: dict, saml_user_id: str):
    # This is a very simple authorization function that just checks if the user has the right role.
    if saml_user_id in allowed_users:
        # This depends on the type of nameID you get. it's also possible that you need
        #  to extract this from an element in the saml_user_data
        return True
    if group_field in saml_user_data and any(
        set(saml_user_data[group_field]) & set(allowed_groups)
    ):
        return True
    return False


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
