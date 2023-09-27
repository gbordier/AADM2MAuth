## first create server app in target tenant
## note select tenant just connects to the AAD tenant
$currentpath=[System.IO.Path]::GetDirectoryName($script:myinvocation.MyCommand.Definition)

## reload previous step output
. $currentpath\0-vars.ps1


## focus on target tenant.

select-adtenant Server
$conf.Apps|?{$_.Tenant -eq "Server"} |%{
	remove-azureadapplication -objectid $_.objectid
}

select-adtenant Client
$conf.Apps|?{$_.Tenant -eq "Client"} |%{
	if ($_.certificatethumbprint) {
		$cert = get-item ( join-path "cert:\currentuser\my" $_.certificatethumbprint)
		if ($cert) {$cert|remove-item}
	}
	remove-azureadapplication -objectid $_.objectid
}
$conf.Apps | %{
$_.objectid=$null
$_.targetspobjectid=$null
$_.appid=$null

}

$conf | convertto-json | set-content $fullconfpath

if (test-path "./validate_token_python")
{
    [pscustomobject]@{
        CLIENT_ID = $clientappdef.AppId
        SERVER_ID = $serverappdef.AppId
        TENANT_ID = $serverappdef.TenantId
    } | convertto-json | set-content "./validate_token_python/config.json" 

}