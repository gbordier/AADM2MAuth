$currentpath=[System.IO.Path]::GetDirectoryName($script:myinvocation.MyCommand.Definition)

## reload previous step output
. $currentpath\0-vars.ps1



$conf.Apps|?{$_.Tenant -eq "Server"} |%{
    $serverapp = $_
}

$conf.Apps|?{$_.Tenant -eq "Client"} |%{
    $clientappdef=$_
    try {
  if ($clientappdef.CredentialType -eq "Password"){
    write-host "retrieving a token for $($clientappdef.name) in target tenant with password"
    $secret = Decrypt -blob $clientappdef.KeyValue

    $token=  get-MsalToken -ClientSecret (ConvertTo-SecureString  -String $secret -AsPlainText -Force )  -ClientId $clientappdef.AppId -TenantId $serverapp.tenantid  -Scopes "$($serverapp.AppId)/.default" -ForceRefresh
  write-host "showing token payload for app secret "
  (Decode-JWT -token $token.AccessToken -token_type access_token).payload
  }
  if ($clientappdef.CredentialType -eq "Certificate"){
    write-host "retrieving a token for $($clientappdef.name) in target tenant with certificate $($clientappdef.CertificateThumbprint)"
    
    $cert=  GetCertificateFromStore -Thumbprint $clientappdef.CertificateThumbprint
    
    $token=get-MsalToken  -ClientCertificate $cert -ClientId $clientappdef.AppId -TenantId $serverapp.tenantid  -Scopes "$($serverapp.AppId)/.default" -ForceRefresh
  }
  write-host "showing token payload"
  (Decode-JWT -token $token.AccessToken -token_type access_token).payload

    }

catch {
  write-host "error $($error[0].exception.message) retrieving token for $($clientappdef.name) in target tenant"
}


}
