# Azure AD Cross-tenant Machine To Machine (also known as S2S) authentication demo

the full documentation for this pattern is located [here](./M2MAUTH.md)

The goal for this is to demonstrate how easy it is to authenticate a "Client" daemon/headless application (non-interactive) managed by a client organization into a "Server" API application that is managed in another Organization / Azure AD Tenant.

This demoe has 2 parts
- the Powershell scripts that prepare and tests everything
- the mini python flask-based web app (in validate_token_python) to demonstrate it actually works

## Demo pre-requisistes


- this script is meant to use Powershell 5 (Windows) because of:
  - the way it handles certificate with Windows Certificate Stores
  - for some obscure reason the AzureAD PSH module does not work on powershell core, I'll add a branch to use Microsoft.Graph for PSH Core psh plugin whenever the cmdlet stabilize out of Beta
- I have added my own JWT decoding module to show the output of the Access Token in the Modules folder

if no config file is provided, one will be created for you.

## Steps

1. Run 1-CreateClientAndServerApps.ps1 which will:
    - read config.json to understand which applications to create, or create one from scratch if non existing
    - Create 
        - An Application (App Registration) in the "Server" AAD Tenant (as a mono tenant app) with its associated AppRoles (aka Application Permissions), 
        - 2 Applications (App Registrations) in the "Client" AAD Tenant (as multi-tenants apps), with their secrets (password or certificate)
    - write all references to the config.json file
    - write appid for server and client apps to the config.json located in the python test web app

2. Wait 30 seconds and launch : 2-CreateServicePrincipals.ps1 which will:
    - read config.json to understand which applications to create, or create one from scratch if non existing
    - Creates
        - Service Principals (Enterprise Applications) for all 3 applications into the Servre AAD Tenant
    - write all references to the config.json file

3. 3-SetAppRoles.ps1 will :
    - read config.json file
    - make sure the server service principal does not allow access if a client has not been granted a role
    - Assign both Client applications service principal to an application role for the server application service principal

4. 4-Test-Auth.ps1 will leverage MSAL.PS module to retrieve tokens 
    - using the credential from the Client AAD Tenant
    - signed with the target AAD tenant
    - tagged with the client AppID
    - set with the server AppID as the audience
    - including assigned roles for the client app


## the Python App

the ./validate_token_python folder is a flask based web app that can be loaded into an azure web app and can validate the token.


what it actually does :

- the Python app reads its own config.json file that has been created by the above script to retrive Application and tenant IDs for the expected tokens
- then it wait for an Authorization header when called via the /hello REST API
- the app extract the access token that is part of the Bearer authorization header
- then is checks:
  - the token has been signed by Azure AD
  - the token hsa the server tenant ID in the idp claim
  - the token has the server app ID in the audience (aud) claim
  - the token has the client app ID in the appid (appid) claim
  - the token has the expected Application role in the roles claim
  - the token has the appcr claim which indicate a certificate has been used to request the token.


It can be run from WSL or Windows  using run_local.sh or in an Azure Web App.
if ran locally, you can use ".\5-Test-Auth-python.ps1" to test local authentication.
if ran from the web app , use  .\5-Test-Auth-python.ps1 -serveruri "https://yourwebapp.azurewebsites.net/hello"

