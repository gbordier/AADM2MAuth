## first create server app in target tenant
## note select tenant just connects to the AAD tenant
$currentpath=[System.IO.Path]::GetDirectoryName($script:myinvocation.MyCommand.Definition)

. $currentpath\0-vars.ps1



select-adtenant Server
$serverappdef= $conf.Apps|?{$_.Tenant -eq "Server"}

if ($serverappdef)
{
    $serversp=retrieveorcreatesp -appdef $serverappdef
}

write-host "looking for client apps in server tenant"
$conf.Apps|?{$_.Tenant -eq "Client"} |%{
    $appdef=$_
    $sp= Get-AADServicePrincipal -Filter "AppId eq '$($appdef.AppId)'"
    if (!$sp){
        write-host "creating service principal for server application $($appdef.Name) in tenant "
        $sp = New-AADServicePrincipal -AppId $appdef.AppId
        
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
