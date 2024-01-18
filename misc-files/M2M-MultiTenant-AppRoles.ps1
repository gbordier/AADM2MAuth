## all in target (server) tenant

$server_appid="8db83c99-524f-4036-8db7-4ea3d5101f25"
$client_appid="824fa74a-f2de-4f9c-90d6-07c7b76dd29e"
$serverapp=Get-MgBetaApplication -Filter "AppId eq '$($server_appid)'"
$serversp=Get-MgBetaServicePrincipal -Filter "AppId eq '$($serverapp.AppId)'"
$clientsp=Get-MgBetaServicePrincipal -Filter "AppId eq '$client_appid'"


New-MgBetaServicePrincipalAppRoleAssignment `
			-servicePrincipalId $clientsp.Id  `
			-AppRoleId $serverapp.AppRoles[0].Id `
			-ResourceId $serversp.Id   `
			-PrincipalId $clientsp.Id


$token=(Get-MsalToken  -ForceRefresh -ClientId $clientsptarget.AppId -ClientSecret (ConvertTo-SecureString -Force -AsPlainText $v) -Scopes "$($serverapp.AppId)/.default" -TenantId  new.pft.ovh ); (Decode-JWT -token_type access_token -token $token.AccessToken).payload

<#
aud      : 8db83c99-524f-4036-8db7-4ea3d5101f25
iss      : https://sts.windows.net/d1d92357-0fd1-4f9d-853e-a2bf3d687614/
iat      : 13/09/2023 5:35:29 pm
nbf      : 13/09/2023 5:35:29 pm
exp      : 13/09/2023 6:40:29 pm
aio      : E2FgYAgU5Djn86JhkeMSW59jr3/uBgA=
appid    : 824fa74a-f2de-4f9c-90d6-07c7b76dd29e
appidacr : 1
idp      : https://sts.windows.net/d1d92357-0fd1-4f9d-853e-a2bf3d687614/
oid      : c9e25e01-6f1f-480e-ba91-1862a11bcc3a
rh       : 0.AUYAVyPZ0dEPnU-FPqK_PWh2FJk8uI1PUjZAjbdOo9UQHyWAAAA.
roles    : {AppRole2}
sub      : c9e25e01-6f1f-480e-ba91-1862a11bcc3a
tid      : d1d92357-0fd1-4f9d-853e-a2bf3d687614
uti      : 2M_1cd7wvkGo06Hk88YkAA
ver      : 1.0
#>