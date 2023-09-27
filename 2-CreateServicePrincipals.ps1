## first create server app in target tenant
## note select tenant just connects to the AAD tenant
$currentpath=[System.IO.Path]::GetDirectoryName($script:myinvocation.MyCommand.Definition)

. $currentpath\0-vars.ps1


function retrieveorcreateapp($appdef) {
    if ($appdef.AppId) {
        $app=Get-AzureADApplication -Filter "AppId eq '$($appdef.AppId)'"    
    
    }
    else{
        $app=Get-AzureADApplication -Filter "DisplayName eq '$($appdef.Name)'"
        if ($app) {
    
        }
        else {
            $app=New-AzureADApplication -DisplayName $appdef.Name   -AvailableToOtherTenants $true
    
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



select-adtenant Server
$serverappdef= $conf.Apps|?{$_.Tenant -eq "Server"}

if ($serverappdef)
{
    $serversp= Get-AzureADServicePrincipal -Filter "AppId eq '$($serverappdef.AppId)'"
    if (!$serversp){
        write-host "creating service principal for server application $($serverappdef.Name) in tenant $(Get-AzureADTenantDetail)"
        $serversp = New-AzureADServicePrincipal -AppId $serverappdef.AppId
    }
    Set-AzureADServicePrincipal -ObjectId $serversp.objectid   -AppRoleAssignmentRequired $true
    $serverappdef | Add-Member -NotePropertyName TargetSPObjectId  -NotePropertyValue $serversp.ObjectId -ErrorAction SilentlyContinue -force 
    write-host "target object sp for server is $($serverappdef.targetspobjectid)"
}

write-host "looking for client apps in server tenant"
$conf.Apps|?{$_.Tenant -eq "Client"} |%{
    $appdef=$_
    $sp= Get-AzureADServicePrincipal -Filter "AppId eq '$($appdef.AppId)'"
    if (!$sp){
        write-host "creating service principal for server application $($appdef.Name) in tenant $(Get-AzureADTenantDetail)"
        $sp = New-AzureADServicePrincipal -AppId $appdef.AppId
        
    }
    if ($sp) {
        write-host "target object sp for client app $($appdef.name) is $($appdef.targetspobjectid)"
    }
    else {
        write-host "could not create service principal for $($appdef.Name) in server tenant"
    }
    $appdef | Add-Member -NotePropertyName TargetSPObjectId  -NotePropertyValue  $sp.ObjectId -force -ErrorAction SilentlyContinue

}


$conf | convertto-json | set-content $fullconfpath
