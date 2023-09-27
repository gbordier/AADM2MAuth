Param ($serveruri="http://localhost:5000")
$currentpath=[System.IO.Path]::GetDirectoryName($script:myinvocation.MyCommand.Definition)

## reload previous step output
. $currentpath\0-vars.ps1



$conf.Apps|?{$_.Tenant -eq "Server"} |%{
    $serverapp = $_
}

$conf.Apps|?{$_.Tenant -eq "Client" } |%{
    $clientappdef=$_
    try {
  if ($clientappdef.CredentialType -eq "Password"){
    write-host "retrieving a token for $($clientappdef.name) in target tenant with password"
    $token=  get-MsalToken -ClientSecret ( ConvertTo-SecureString -AsPlainText -Force (DecryptToken $clientappdef.KeyValue)) -ClientId $clientappdef.AppId -TenantId new.pft.ovh  -Scopes "$($serverapp.AppId)/.default"
  write-host "showing token payload for app secret "
  (Decode-JWT -token $token.AccessToken -token_type access_token).payload
  }
  if ($clientappdef.CredentialType -eq "Certificate"){
    write-host "retrieving a token for $($clientappdef.name) in target tenant with certificate $($clientappdef.CertificateThumbprint)"
    $token=get-MsalToken  -ClientCertificate (dir (join-path "Cert:\CurrentUser\my" $clientappdef.CertificateThumbprint)) -ClientId $clientappdef.AppId -TenantId new.pft.ovh  -Scopes "$($serverapp.AppId)/.default"
  }
  write-host "testing token payload with local python app use ./run_local.sh to start the app "
(curl -H @{"Authorization"= "Bearer $($token.accesstoken)" } -uri "$serveruri/hello").Content
    }

catch {
  write-host "error $($error[0].exception.message) retrieving token for $($clientappdef.name) in target tenant"
}


}
