## first create server app in target tenant
## note select tenant just connects to the AAD tenant
$currentpath=[System.IO.Path]::GetDirectoryName($script:myinvocation.MyCommand.Definition)

## reload previous step output
. $currentpath\0-vars.ps1


## focus on target tenant.

select-adtenant Server
$conf.Apps|?{$_.Tenant -eq "Server"} |%{
    $serversp = Get-AzureADServicePrincipal -ObjectId $_.TargetSPObjectId
    ## checking it locked against non approles
    Set-AzureADServicePrincipal -ObjectId $serversp.ObjectId -AppRoleAssignmentRequired $true 
}


$conf.Apps|?{$_.Tenant -eq "Client"} |%{
    $clientappdef=$_
    write-host "creating service principal in target tenant for client app if not exists"
    $clientsp=get-AzureADServicePrincipal -ObjectId $_.TargetSPObjectId
    if ($clientsp) {
        $clientappdef | Add-Member -NotePropertyName TargetSPObjectId  -NotePropertyValue $clientsp.ObjectId -ErrorAction SilentlyContinue -force 
        write-host "assigning app role to client app $($clientsp.objectid )in target tenant for app $($serversp.objectid) if not assigned"
        $ass = Get-AzureADServiceAppRoleAssignment -ObjectId $clientsp.ObjectId -All $true |?{$_.ResourceId -eq $serversp.objectId}
        if (!$ass){
	
            $ass=New-AzureADServiceAppRoleAssignment -objectid $clientsp.ObjectId -principalid $clientsp.ObjectId -resourceid $serversp.ObjectId -Id $serversp.AppRoles[0].id
        }
    }
    else {
        write-host "could not find client app in tenant source $((Get-AzureADTenantDetail).objectid)"
    }
}
## create new app key for client app


$conf | convertto-json | set-content $fullconfpath
