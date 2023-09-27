 $q=$($script:myinvocation)
 if ($q.CommandOrigin -ne "Internal"  )
 {
    write-host "warning, this sccript is meant to load variables and functions into the current shell, it should be dot-sourced use `n`". .\$($q.Mycommand)`""
    write-host "exiting now, please begin with 1-xxx script"
    write-host "note : password secrets will be encrypted with DPAPI on windows which will only be decrypted under the same windows profile"
    return
 }

$currentpath=[System.IO.Path]::GetDirectoryName($script:myinvocation.MyCommand.Definition)
$fullconfpath = join-path  $currentpath    "config.json"


$conf= gc -Path $fullconfpath | convertfrom-json
if (!$conf)
{
    write-host "createing .\config.json file with default appnames for this demo"
    write-host "this file will be amended by the scripts"
    $apps=@()
    $app=@{ Name = "AAdXTenantAuth-ClientPwd" ; Tenant = "Client" ;CredentialType = "Password"}
    $apps+=$app
    $app=@{ Name = "AAdXTenantAuth-ClientCert" ; Tenant = "Client" ;CredentialType = "Certificate"}
    $apps+=$app
    
    $app=@{ Name = "AAdXTenantAuth-Server" ; Tenant = "Server" }
    $apps+=$app
    $conf = [pscustomobject]@{
        Tenants =@([PSCustomObject]@{
            
            Name = 'Server'
            CredentialType = "AccessToken"
        }
        ,[PSCustomObject]@{
            Name = "Client"
            CredentialType = "AccessToken"
        })        
        Apps = $apps
    }
    

}



Function EncryptToken($token)
{
	Add-Type -AssemblyName System.Security;
	$encrypteddata=[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::ASCII.GetBytes($token),$null,'CurrentUser')
    return ([System.Convert]::ToBase64String($encrypteddata))
}

Function DecryptToken($blob)
{
	Add-Type -AssemblyName System.Security;
	$token=[Text.Encoding]::ASCII.GetString([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($blob), $null, 'CurrentUser'))
    return $token
}


function select-ADtenant($tenantname)
{
	write-host "looking for tenant $tenantname"
    $conf.Tenants|?{$_.Name -eq $tenantname} |%{
        $tenant=$_


	write-host "connecting to tenant $($tenant.tenantid)"
        while (!$tenant.TenantId) {
            $tenant | Add-Member -NotePropertyName TenantId   -NotePropertyValue (read-host "please enter the tenant id for $($tenant.Name)") -ErrorAction SilentlyContinue 
            
        }

        if ($tenant.AccessToken -and $tenant.Tenantid){
            $aadconn= Connect-AzureAD -TenantId $tenant.TenantId -AadAccessToken (DecryptToken $tenant.AccessToken) -accountid $tenant.accountid
        }else{
            ## try interactive 
            $aadconn= Connect-AzureAD -TenantId $tenant.TenantId
        }
        "TenantId","TenantDomain","AccessToken","AccountId"  | %{
                  $tenant  | Add-Member -NotePropertyName $_   -NotePropertyValue $null  -ErrorAction SilentlyContinue 
		}
		try {
	    get-azureadtenantdetail -erroraction silentlycontinue | out-null
		}
        catch {
                write-host "bad token"
                $aadconn=$null
                $tenant.accesstoken=$null
        }
	    
            if ($aadconn)
            {

                  $tenant.tenantid = $aadconn.tenantid
                  $tenant.tenantdomain = $aadconn.tenantdomain
		  $tenant.accountid =  $aadconn.account.id
                  $tenant.AccessToken = encrypttoken (([Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens.Values[0].AccessToken))
                  $conf | convertto-json | set-content $fullconfpath
                
            }

        

        
    }

}


$conf | convertto-json | set-content $fullconfpath
