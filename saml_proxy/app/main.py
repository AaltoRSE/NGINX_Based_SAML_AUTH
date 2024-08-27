from typing import Union
from fastapi.security import OAuth2PasswordBearer
from fastapi import FastAPI, Request, Response, Security, HTTPException, WebSocket
from starlette.responses import RedirectResponse
from starlette.middleware.sessions import SessionMiddleware
from starlette.middleware.authentication import AuthenticationMiddleware
import starlette.status as status
from starlette.requests import HTTPConnection


from security.session import SessionHandler
from security.auth import SAMLSessionBackend, clean_session, authorize_user
from security.saml import prepare_from_fastapi_request, saml_settings

from onelogin.saml2.auth import OneLogin_Saml2_Auth


import logging


def get_authed_user(conn: HTTPConnection):
    logging.info(conn.user)
    if not conn.user.is_authenticated:
        credentials_exception = HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="No user authenticated",
        )
        raise credentials_exception
    return conn.user


# Debugging imports
import traceback

session_handler = SessionHandler()
app = FastAPI()

app.add_middleware(
    AuthenticationMiddleware, backend=SAMLSessionBackend(session_handler)
)

app.add_middleware(SessionMiddleware, secret_key="some-random-string", max_age=None)

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s", level=logging.DEBUG
)


@app.middleware("http")
async def logger_middleware(request: Request, call_next):
    path = request.url.path
    method = request.method
    log_message = f"Received request: {method} {path}"
    query = request.url.query
    logging.info(log_message)
    logging.info(request.headers)
    logging.info(query)
    response = await call_next(request)
    return response


@app.get("/saml/auth")
async def auth_test(request: Request):
    # Obtain the auth manually here, because we want to provide
    # Information about the authentication status, and using security would make this fail with Unauthorized
    # Responses...
    logging.info("Got auth request")
    if request.user.is_authenticated:
        logging.info(f"User is:{request.user.username}")
        return {"authed": True, "user": request.user.username}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )


@app.websocket("/saml/auth")
async def websocket_endpoint(websocket: WebSocket, request: Request):
    if request.user.is_authenticated:
        logging.info(f"User is:{request.user.username}")
        return {"authed": True, "user": request.user.username}
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated"
        )


@app.get("/saml/login")
async def login(request: Request):
    req = await prepare_from_fastapi_request(request)
    auth = OneLogin_Saml2_Auth(req, saml_settings)
    callback_url = auth.login()
    response = RedirectResponse(url=callback_url)
    return response


@app.post("/saml/acs")
async def saml_callback(request: Request):
    logging.info("SAML Auth requested")
    req = await prepare_from_fastapi_request(request, True)
    auth = OneLogin_Saml2_Auth(req, saml_settings)
    auth.process_response()  # Process IdP response
    errors = auth.get_errors()  # This method receives an array with the errors
    logging.info("SAML processed")
    if len(errors) == 0:
        if not auth.is_authenticated():
            # This check if the response was ok and the user data retrieved or not (user authenticated)
            return "User Not authenticated"
        else:
            sessionData = {}
            sessionData["samlUserdata"] = auth.get_attributes()
            sessionData["samlNameId"] = auth.get_nameid()
            sessionData["samlNameIdFormat"] = auth.get_nameid_format()
            sessionData["samlNameIdNameQualifier"] = auth.get_nameid_nq()
            sessionData["samlNameIdSPNameQualifier"] = auth.get_nameid_spnq()
            sessionData["samlSessionIndex"] = auth.get_session_index()
            if not authorize_user(
                sessionData["samlUserdata"], sessionData["samlNameId"]
            ):
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="User not allowed to use this resource",
                )
            session_key = session_handler.create_session(sessionData)
            logging.info("Session key created, adding to request session")
            request.session["key"] = session_key
            request.session["invalid"] = False
            forwardAddress = f"/"
            logging.info("Forwarding to /")
            return RedirectResponse(
                url=forwardAddress, status_code=status.HTTP_303_SEE_OTHER
            )
    else:
        logging.error(
            "Error when processing SAML Response: %s %s"
            % (", ".join(errors), auth.get_last_error_reason())
        )
        return "Error in callback"


@app.get("/saml/metadata")
async def metadata():
    metadata = saml_settings.get_sp_metadata()
    return Response(content=metadata, media_type="text/xml")


@app.get("/saml/slo")
async def saml_logout(request: Request, user: any = Security(get_authed_user)):
    req = await prepare_from_fastapi_request(request, True)
    auth = OneLogin_Saml2_Auth(req, saml_settings)
    name_id = session_index = name_id_format = name_id_nq = name_id_spnq = None
    logging.info(user)
    userData = user.get_user_data()
    if "samlNameId" in userData:
        name_id = userData["samlNameId"]
    if "samlSessionIndex" in userData:
        session_index = userData["samlSessionIndex"]
    if "samlNameIdFormat" in userData:
        name_id_format = userData["samlNameIdFormat"]
    if "samlNameIdNameQualifier" in userData:
        name_id_nq = userData["samlNameIdNameQualifier"]
    if "samlNameIdSPNameQualifier" in userData:
        name_id_spnq = userData["samlNameIdSPNameQualifier"]
    url = auth.logout(
        name_id=name_id,
        session_index=session_index,
        nq=name_id_nq,
        name_id_format=name_id_format,
        spnq=name_id_spnq,
    )
    logging.info(f"Redirecting to {url}")
    request.session["LogoutRequestID"] = auth.get_last_request_id()
    return RedirectResponse(url=url)


@app.get("/saml/sls")
async def saml_logout(request: Request, user: any = Security(get_authed_user)):
    req = await prepare_from_fastapi_request(request, True)
    auth = OneLogin_Saml2_Auth(req, saml_settings)
    logging.info(req)
    request_id = None
    if "LogoutRequestID" in request.session:
        request_id = request.session["LogoutRequestID"]
    dscb = lambda: clean_session(request.session)
    url = auth.process_slo(request_id=request_id, delete_session_cb=dscb)
    logging.info(url)
    errors = auth.get_errors()
    if len(errors) == 0:
        if url is not None:
            # To avoid 'Open Redirect' attacks, before execute the redirection confirm
            # the value of the url is a trusted URL.
            return RedirectResponse(url)
        else:
            # Return back to main page
            return RedirectResponse(url="/")
    elif auth.get_settings().is_debug_active():
        error_reason = auth.get_last_error_reason()
        return error_reason
    else:
        logging.error(auth.get_last_error_reason())
