# Machine to Machine (or Server to Server) authentication with Microsoft Entra ID (a.k.a Azure Active Directory)

## Entra ID Applications and service principals reminder

### Entra ID Application

- An Entra ID (AAD) Application is represented as an Application Registration in the Entra ID portal
- An AAD Application is an object that has:
  - a Display Name (can be changed)
  - an immutable AppID
  - an ObjectID (like all AAD objects)
  - it defines  properties such as Application Roles / Permissions
  - it is created in one tenant but can be marked as "Multi Tenant"
  - it has an Application Manifest that stores multiple  properties.

- An Entra ID application is necessary  to authenticate users or other application and validate the said authentication.
- An  Entra ID application can also authenticate itself to another one using a secret (password) or certificate that is stored with the Application Object

### Entra ID Service Principal

An Entra ID Service Principal is another kind of AAD object that is represented as an "Entreprise Application" in the portal :
- it is created from an AAD Application (the portal creates one automatically when an application is created)
- The Goal for a Service Principal is for the parent application to be assisgned a role or be given permission or. Role Assignment always reference service principal objectID for trustee or resource, not application IDs.
- it can be created for the application in the local tenant or any other tenant if the application is marked as "Multi-Tenant"

## Cross Tenant Discussion

While an app is created in one tenant, service principals for this app can be created in any number of tenants.

Creating a service principal for an app in one tenant means:
- a user can authenticate itself to the parent app in this tenant
- the app itself can authenticate itself in this tenant

# Machine to Machine (S2S) authentication 

the Machine to Machine or Server to Server pattern typical use case if for non-interactive use cases where one application needs to consume a service (or API) delivered by another application (or server).
This pattern aligns with the **OAuth 2.0** "**Client Credential Flow**" which ia the simpler use case where only the Client (a server) needs to authenticate to another Server with no end user involved.

## Client Credential Flow
At a very basic level, the Client Credential steps are:
- Client authenticates against Azure AD to get an access token usinh a secret or a certificate
- Client sends the access token as an "Authorization" Bearer header in the HTTP query to the server API
- Server validates token by validating the signature with the public signing keys for the target AAD instance (available on the public AAD endpoint) then can checks if:
  - the token hsa the server tenant ID in the idp claim
  - the token has the server app ID in the audience (aud) claim
  - the token has the client app ID in the appid (appid) claim
  - the token has the expected Application role in the roles claim
  - the token has the appcr claim which indicate a certificate has been used to request the token.

# Making it work across tenant

In situations where the consumer is in one tenant (customer) and the producer is in another tenant (provider) the same principle apply. To some extent this also is a very good way of understanding how AzureAD application authentication works.

![schema 1]('./img/Cross-Tenant-Authentication.jpg')

In the above schema:
- the provider has created an Application and a Service Principal for this application in its tenant
- the customer has created an Application in its tenant and marked it as "MultiTenant"
- the provider has created a Service Principal for the customer application in its tenant
* This allows the client app to authenticate against the provider's tenant for any Application in the provider tenant that has a service principal present,  whether the app has been declared in the provider tenant or elsewhere (such as Microsoft Graph for instance) * 


