# SAML based authentication restriction using NGINX

This is a small example on how a service can be hidden behind an authentication scheme using nginx.

The `test` app (which is currently just a hello world app), will only be served if the user has authed against the SAML service giving authentication.

The `saml_proxy` app, initializes a SAML authentication protocol, which forwards the request to the SAML IdP.

Once the IdP successfully authenticates the session, the SAML app will inform nginx, that the user is authenticated and can be pased on.

In its current setup, the `saml_proxy` app also needs to perform authorization checks, since all users that get authentication from the selected IdP will have full access to the app (this might be ok, but it depends on the actuall application)

## Setup

You will need a working SAML IdP for the saml proxy to work. Other than that, your backend cannot listen to any `/saml/*` endpoints, as they will be routed to the saml proxy.

### Certificate setup

To use SAML you will need to set up certificates as follows:

```
mkdir saml_proxy/app/saml/certs
cd saml_proxy/app/saml/certs
openssl req -new -x509 -days 3652 -nodes -out sp.crt -keyout sp.key
```

Enter the requested details. Depending on your IdP you might need to put in specific data there.

### SAML Settings setup

Upate the `saml_proxy/app/saml/settings.json` file according to your IdP settings and your Service Provider (SP) settings (most likely mainly the URLs (they are likely https as well), but definitely the `x509cert` field for your IdP).

### Dev Setup

#### Setup keycloak

After starting the containers for the first time, do the following:

** Login **

URL: http://127.0.0.1:8081/
Administration Console

- Username: admin
- password: admin

** Obtain realm Certificate **

- Configure(left menu) -> Realm Settings -> Endpoints - SAML 2.0 .. Metadata
  - copy `<ds:x509Certificate>` tab data
  - paste the data under the project folders `app/saml/settings.json` replacing the `idp -> x509cert` field

** Set up a client **

- go to "127.0.0.1:3000/saml/metadata"
- save the file as metadata.xml
- In the keycloak administration console:
  - Manage (left Menu) -> Clients -> Import Client -> Browse
  - select the metadata file you created

** Configure the client **

- Manage (left menu) -> Client Scopes -> role_list -> Mappers -> role_list
  - Activate "single role attribute"
  - Save
- Manage -> Clients -> Roles -> Create Role
  - Role Name : User -> Save

** Create a user **

- Manage (left Menu) -> Users -> Add User
  - UserName : test-user
  - Create
- Manage (left Menu) -> Users -> test-user -> Credentials -> Add Password
  - (select a password), deactivate temporary
- Manage (left Menu) -> Users -> test-user -> Role Mapping -> Assign role -> Filter By Clients
  - Select the User role created before

This should be it

### SAML Proxy app

The app initializes a simple SAML authentication flow, which creates a cookie that is used to authenticate the user. To add authorization (i.e. restriction to specific users or user groups) modify the `authorize_user` function in the `security/auth.py` module according to your needs.

### HTTPS

The app is expected to run behind some form of https proxy (most likely run on a kubernetes cluster which terminates the https connection before it reaches the app).
If you need to use your own https, you can add the https setup to nginx.
