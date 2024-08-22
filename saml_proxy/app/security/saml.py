from fastapi import Request
from onelogin.saml2.settings import OneLogin_Saml2_Settings
import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))
print(BASE_DIR)
SAML_DIR = os.path.join(BASE_DIR, "saml")

saml_settings = OneLogin_Saml2_Settings(
    settings=None, custom_base_path=SAML_DIR, sp_validation_only=True
)


async def prepare_from_fastapi_request(request: Request, debug=False):
    rv = {
        "http_host": request.url.hostname,
        "server_port": request.url.port,
        "script_name": request.url.path,
        # Need to find the correct way to do this...
        "post_data": {},
        "get_data": dict(request.query_params),
        # Advanced request options
        # "https": ""  # Uncomment if you are running a server using https!
        # "request_uri": "",
        "query_string": request.url.query,
        # "validate_signature_from_qs": False,
        # "lowercase_urlencoding": False
    }
    form_data = await request.form()
    if "SAMLResponse" in form_data:
        SAMLResponse = form_data["SAMLResponse"]
        rv["post_data"]["SAMLResponse"] = SAMLResponse
    if "RelayState" in form_data:
        RelayState = form_data["RelayState"]
        rv["post_data"]["RelayState"] = RelayState

    return rv
