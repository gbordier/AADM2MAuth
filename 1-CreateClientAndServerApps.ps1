## first create server app in target tenant
## note select tenant just connects to the AAD tenant
$currentpath=[System.IO.Path]::GetDirectoryName($script:myinvocation.MyCommand.Definition)

. $currentpath\0-vars.ps1


function retrieveorcreateapp($appdef,[switch]$multiTenant) {
    if ($appdef.AppId) {
        $app=Get-AzureADApplication -Filter "AppId eq '$($appdef.AppId)'"    
    
    }
    else{
        $app=Get-AzureADApplication -Filter "DisplayName eq '$($appdef.Name)'"
        if ($app) {
    
        }
        else {
            $app=New-AzureADApplication -DisplayName $appdef.Name   -AvailableToOtherTenants ([book] $multiTenant)
    
        }
}
    $appdef | Add-Member -NotePropertyName AppId  -NotePropertyValue $null -ErrorAction SilentlyContinue 

    "AppId","ObjectId","TenantId","App" |%{
            $appdef | Add-Member -NotePropertyName $_   -NotePropertyValue $null -ErrorAction SilentlyContinue 
        }

    $appdef.appid = $app.AppId
    $appdef.objectId = $app.ObjectId
    $appdef.tenantid =  (Get-AzureADTenantDetail).ObjectId
    #$appdef.app = $app

    return $app
}


function CreateSecret($app) {
    "KeyId","KeyValue","CertificateThumbprint" |%{
        $app | Add-Member -NotePropertyName $_   -NotePropertyValue $null -ErrorAction SilentlyContinue
    }
    if ($app.credentialtype -eq "Certificate" -and  $app.CertificateThumbprint)
	{   
	write-host "checkinf if certificate $($app.certificatethumbprint) is present"
	$cert=get-item (join-path  "Cert:\CurrentUser\my" $app.certificatethumbprint) 
	if (!$cert) { write-host "certificate not found locally " 
			$app.CertificateThumbprint = $null }
	}
    if ($app.credentialtype -eq "Certificate" -and -not $app.CertificateThumbprint) {
        foreach ($cert in  (dir Cert:\CurrentUser\my |?{$_.subject -eq $app.Name -and !$_.HasPrivateKey}) ){
            remove-item $_ -Force -Confirm:$false
        }
        $cert = dir Cert:\CurrentUser\my |?{$_.Subject -eq "CN=$($app.Name)"} | select -First 1
            
        if (!$cert ) {
	        write-host "creating cert with Microsoft Enhanced RSA and AES Cryptographic Provider"
            $cert=New-SelfSignedCertificate -DnsName $app.Name -CertStoreLocation "Cert:\CurrentUser\My" -KeySpec Signature -HashAlgorithm SHA256 -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"  -KeyExportPolicy NonExportable  -KeyLength 2048
            try {
                write-host "checking we can sign data with sha256 for this certificate"
                $sig=$cert.PrivateKey.SignData(([byte] "1","2"), [System.Security.Cryptography.HashAlgorithmName]::SHA256, [System.Security.Cryptography.RSASignaturePadding]::Pkcs1)
            }
            catch {
                write-host "cannot sigh with sha256 , trying sha1 or change certificate provider"
                exit
            }
	        write-host "cert created with thumbprint $($cert.thumbprint)"
        }
	    else { write-host "found existing cert "}
        ## upload certificate and set customkeyid as the certificate thumbprint
        $secret=New-AzureADApplicationKeyCredential -ObjectId $app.ObjectId -CustomKeyIdentifier ( [System.Convert]::ToBase64String( $cert.GetCertHash())) -Type AsymmetricX509Cert -Usage Verify -Value ([System.Convert]::ToBase64String( $cert.RawData)) -EndDate ($cert.NotAfter)
        if ($secret) {
            $app.CertificateThumbprint = $cert.Thumbprint
            $app.KeyId = $secret.KeyId
        }

    }
    if ($app.credentialtype -eq "Password" -and -not $app.KeyId) {
        
        ## remove existing secrets
        Get-AzureADApplicationPasswordCredential -ObjectId $app.objectid |%{
            Remove-AzureADApplicationPasswordCredential -ObjectId $app.objectid -KeyId $_.KeyId   | out-null
        }

        $secret=New-AzureADApplicationPasswordCredential -ObjectId $app.ObjectId 
        if ($secret)
        {
            $app.KeyId = $secret.KeyId        
            $app.KeyValue= (EncryptToken $secret.Value )
        }   
        
        
    }
}

select-adtenant Server
$serverappdef= $conf.Apps|?{$_.Tenant -eq "Server"}

$serverapp=retrieveorcreateapp -Appdef $serverappdef
if ($serverapp) {

    if (!$serverapp.AppRoles )
    {
        $AppRoles=@( [PSCustomObject]@{
        
            
                "AllowedMemberTypes"= @(
                    "Application"
                )
                "Description"= "First Role for test app."
                "DisplayName"= "Role1"
                "Id"= "$(new-guid)"
                "IsEnabled"= "true"
                "Value"= "Role1"
            },
            [PSCustomObject]@{
                "AllowedMemberTypes"= @(
                    "Application"
                )
                
                "Description"= "Second Role for test app."
                "DisplayName"= "Role2"
                "Id"= "$(new-guid)"
                "IsEnabled"= "true"
                "Value"= "Role2"
            }
        )
        write-host "adding default roles to server application"
	 Set-AzureADApplication -objectid  $serverapp.objectid  -AppRoles $AppRoles 
    }
}

select-adtenant Client
$conf.Apps|?{$_.Tenant -eq "Client"} |%{
    $clientappdef=$_
    write-host "creating or retrieving application $($clientappdef.Name) from Source tenant $((Get-AzureADTenantDetail).ObjectId)"
    $clientapp = retrieveorcreateapp -Appdef $clientappdef -multiTenant
    if ($clientapp) {
        CreateSecret -app $clientappdef | out-null
    }
    else {
        write-host "could not find client app in tenant source $(Get-AzureADTenantDetail)"
    }
}

$conf | convertto-json | set-content $fullconfpath

$clientappdef = $conf.Apps|?{$_.Tenant -eq "Client" -and $_.CredentialType -eq "Certificate"} 
$targetpath=join-path $currentpath "validate_token_python"
if (test-path $targetpath)
{
    [pscustomobject]@{
        CLIENT_ID = $clientappdef.AppId
        SERVER_ID = $serverappdef.AppId
        TENANT_ID = $serverappdef.TenantId
    } | convertto-json | set-content ( join-path  $targetpath  "config.json" )

}
