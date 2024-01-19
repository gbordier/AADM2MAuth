#!/bin/sh
prefix=$(az account show --query "user.name" | cut -d'@'  -f1  | tr -d '\"' )
location="northeurope"
az webapp up --runtime PYTHON:3.9 --sku B1 --logs --location $location  --os-type Linux -g ${prefix}_rg_flaskwebapp -n $prefix-flaskwebapp

echo 'To test the app run:\
on windows where the certificate is installed :
get an AAD token with\
$conf = gc "..\config.json"|convertfrom-json\

$clientappdef = $conf |?{$_.CredentialType -eq "Certificate"}\
$serverapp=(gc ..\config.json| convertfrom-json )| ?{$_.Tenant -eq "Target" }
$cert=dir (join-path "Cert:\CurrentUser\my" $$clientappdef.CertificateThumbprint)\
$token=(get-MsalToken  -ClientCertificate $cert -ClientId $clientappdef.ClientId -TenantId $serverapp.TenantId -Scopes "$($serverapp.AppId/.default" ).AccessToken \
curl https://$prefix-flaskwebapp.azurewebsites.net/  -H "Authorization: Bearer $token""
'
