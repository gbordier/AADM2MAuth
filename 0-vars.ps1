install-module msal.ps , az.resources -Confirm:$false  -Scope CurrentUser
import-module ./JWT

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


if (test-path $fullconfpath) {
    $conf= gc -Path $fullconfpath | convertfrom-json
}
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
            CredentialType = ""
            TenantId =""
        }
        ,[PSCustomObject]@{
            Name = "Client"
            CredentialType = ""
        })        
        Apps = $apps
    }
    

}


<#
.SYNOPSIS
Load administrative Credentials to connect to AAD

.DESCRIPTION
preference is always certficiate, if not sepecified we will try to load from the store or load from a file

.EXAMPLE
An example

.NOTES
General notes
#>
function Load-Credentials($conf)
{
    foreach ($tenant in $conf.Tenants)
    {
        if (!$tenant.TenantId)
        {
            $tenant | Add-Member -NotePropertyName TenantId   -NotePropertyValue ""  -ErrorAction SilentlyContinue 
            $tenant.tenantid=(read-host "please enter the tenant id for $($tenant.Name) Tenant")
            write-host "tenant id is now $($tenant.tenantid)"
        }
        if ($tenant.CredentialType -eq "Certificate" -and $tenant.CertificateThumbprint -and $tenant.CredentialAppId)
        {
            $cert=GetCertificateFromStore -thumbprint $tenant.CertificateThumbprint

        }
        if ($tenant.CredentialType -eq "")
        {
            $YN="N"
            $YN=Read-Host "is there a Certificate and AppId to connect to $($tenant.Name) [$($tenant.TenantId)] [Y/N]" 
            if ($YN -eq "Y") {
                $AppId=Read-Host "Enter AppId linked to certificate to connect to $($tenant.Name)" 
                $tenant.CredentialType="Certificate"
                $tenant.CredentialAppId = $appid
            }
        }
        if ($tenant.CredentialType -eq "Certificate"  -and $tenant.CertificateThumbprint -and $tenant.CredentialAppId)
        {
           $cert =GetCertificateFromStore -Thumbprint $tenant.CertificateThumbprint
           $appid = $tenant.CredentialAppId
        }
        if (!$cert) {

        
                $CertPath=read-host "Enter Certificate Path to connect to $($tenant.Name)"
                if ($AppId -and $CertPath -and (test-path $certPath))
                {
                    $cert=Get-PfxCertificate -FilePath $CertPath
                    write-host "certificate loaded"

                }
        }
        
        if ($cert -and $cert.HasPrivateKey -and $tenant.CredentialAppId) {

            write-host "testing connection with appid $($tenant.CredentialAppId) and certificate $($cert.thumbprint) and authority https://login.microsoftonline.com/$($tenant.TenantId)"                    
            $tok=Get-MsalToken  -ClientId $appid  -ClientCertificate $cert  -Authority "https://login.microsoftonline.com/$($tenant.TenantId)"
            if ($tok){
                $tenant | Add-Member -NotePropertyName CertificateThumbprint   $cert.Thumbprint -ErrorAction SilentlyContinue 
                # use X509 store to persist cetificate instead of config file
                #                        $tenant | Add-Member -NotePropertyName Certificate   [System.Convert]::ToBase64String($cert) -ErrorAction SilentlyContinue 
                $tenant | Add-Member -NotePropertyName CredentialAppId   $AppId -ErrorAction SilentlyContinue 

                $tenant.CredentialType="Certificate"
                $storeName = [System.Security.Cryptography.X509Certificates.StoreName]::My
                $storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
                $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, $storeLocation)
                $store.Open("ReadWrite")
                $store.Add($cert)
            }
            else {
                write-host "could not get access token from certificate $($cert.thumbprint) and appid $appid"
                throw
            }
        }

            
        
    }
     
}


function Encrypt($text)
{
    if ($PSVersionTable.Platform -ne "Unix")
    {
        return EncryptWin -text $text
    }
    else {
        return EncryptUnix -text $text
    }
}

function Decrypt($blob)
{
    if ($PSVersionTable.Platform -ne "Unix")
    {
        return DecryptWin -blob $blob
    }
    else {
        return DecryptUnix -blob $blob
    }
}

#region WindowsSpecific

<## this is only for Windows #>
Function EncryptWin($text)
{
	Add-Type -AssemblyName System.Security;
	$encrypteddata=[Security.Cryptography.ProtectedData]::Protect([Text.Encoding]::ASCII.GetBytes($token),$null,'CurrentUser')
    return ([System.Convert]::ToBase64String($encrypteddata))
}

function EncryptUnix($text)
{
    $cert=GetCertificateFromStoreOrCreateSelfSigned -Name "CN=localhost" 
    $blob=[System.Convert]::ToBase64String($cert.PublicKey.Key.Encrypt( [System.Text.Encoding]::ASCII.GetBytes($text) , [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1) )
    return $blob
}
function DecryptUnix($blob)
{
    $cert=GetCertificateFromStoreOrCreateSelfSigned -Name "CN=localhost" 
    $text=[System.Text.Encoding]::ASCII.GetString( $cert.PrivateKey.Decrypt( [System.Convert]::FromBase64String($blob) , [System.Security.Cryptography.RSAEncryptionPadding]::Pkcs1))
    return $text
}


Function DecryptWin($blob)
{
	Add-Type -AssemblyName System.Security;
	$token=[Text.Encoding]::ASCII.GetString([Security.Cryptography.ProtectedData]::Unprotect([Convert]::FromBase64String($blob), $null, 'CurrentUser'))
    return $token
}
#endregion

<#
.SYNOPSIS
PSH version independent AAD connection function

.DESCRIPTION
Long description

.PARAMETER tenant
Parameter description
tenant is a structure that has the following members
- TenantId
- AccountId
the following are optionnal
- TenantDomain
- AccessToken
- AccessTokenExpiration


.PARAMETER devicelogin
Parameter description

.PARAMETER useaccesstoken
Parameter description
try to manage / store / retrieve access token from/to the config file to avoid interactive login


.EXAMPLE
An example

.NOTES
General notes
Windows can ues certificates from the store, it can also do interafctive login without device code
#>
function Connect-AAD($tenant,$devicelogin,[switch] $useaccesstoken)
{
    $p=@{}
    $CertAuthAvailable=$false

    $p['TenantId'] = $tenant.TenantId

    
    if ($tenant.CertificateThumbprint -and $tenant.CredentialAppId  ) {
        ## $p["Certificate"]=[System.Convert]::FromBase64String($tenant.Certificate)
        $storeName = [System.Security.Cryptography.X509Certificates.StoreName]::My
        $storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, $storeLocation)
        $store.Open("Readonly")
        if ($store.Certificates |?{$_.Thumbprint -eq $tenant.CertificateThumbprint -and $_.HasPrivateKey} )
        {
            $p["ApplicationId"]=$tenant.CredentialAppId
            $p["CertificateThumbprint"]=$tenant.CertificateThumbprint
            $CertAuthAvailable=$true
            $devicelogin = $false
        }

    }
    else {
        $p["AccountId"] = $tenant.AccountId
    }


    if ($devicelogin){
        $p["DeviceAuth"]=$true
    }


    if ($useaccesstoken -and `
    $tenant.accesstoken -and $tenant.AccessTokenExpiration -and $tenant.AccessTokenExpiration -gt (get-date) )
    {
        $p["AccessToken"]=DecryptWin ($tenant.accesstoken)
    }


    if ($PSVersionTable.PSEdition -eq "Core")
    {
        write-host "connecting with $($p["ApplicationId"]) and certificate $($p["CertificateThumbprint"])"
        $aadconn = Connect-AzAccount @p
        if ($aadconn) {
            $context = Get-AzAccessToken
            if ($useaccesstoken -and  (-not $p["AccessToken"]) ) {
                    $tenant.AccessTokenExpiration = $context.ExpiresOn
                    if ($PSVersionTable.Platform -ne "Unix") {
                        $tenant.AccessToken = encryptWin -text ( $context.token)
                    }
            }
            $tenant.tenantid = $context.TenantId
            $tenant.accountid =   $context.UserId

        }
    }
    else{

   
        $aadconn= Connect-AzureAD @p
        if ($aadconn) {
            if ($useaccesstoken ) {
                $tenant.AccessTokenExpiration = (get-date).AddMinutes(59)        
                $tenant.AccessToken = encryptwin  -text (([Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens.Values[0].AccessToken))
            }
            $tenant.tenantid = $aadconn.tenantid
            $tenant.tenantdomain = $aadconn.tenantdomain
            $tenant.accountid =  $aadconn.account.id
            
        }
        

        
    }
    return $aadconn
}

function ListCertificatesFromStore()
{
    if ($PSVersionTable.Platform -eq "Unix")
    {
        $storeName = [System.Security.Cryptography.X509Certificates.StoreName]::My
        $storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, $storeLocation)
        $store.Open("Readonly")
        $certs=$store.Certificates 
        
        
    }
    else
    {
        if ($Name)
        {
            $certs=dir  Cert:\CurrentUser\My 
        }
    }
    return $certs
}

function GetCertificateFromStoreOrCreateSelfSigned($Name)
{
    $cert=GetCertificateFromStore -Name $Name
    if (!$cert) {
        $cert=CreateSelfSignedCertificate -subject $Name
    }
    return $cert
}

function GetCertificateFromStore (
    [Parameter(Mandatory, ParameterSetName = 'ThumbPrint')]
    [string] $Thumbprint ,
    [Parameter(Mandatory, ParameterSetName = 'Name') ]
    [string] $Name 
    
    )
{
    if ($PSVersionTable.Platform -eq "Unix")
    {
        $storeName = [System.Security.Cryptography.X509Certificates.StoreName]::My
        $storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, $storeLocation)
        $store.Open("Readonly")
        if ($Name)
        {
            $cert=$store.Certificates |?{$_.Subject -eq $Name -and $_.HasPrivateKey}
        }
        else
        {
            $cert=$store.Certificates |?{$_.Thumbprint -eq $Thumbprint -and $_.HasPrivateKey}
        }
        
    }
    else
    {
        if ($Name)
        {
            $cert=dir  Cert:\CurrentUser\My | ?{$_.Subject -eq $Name -and $_.HasPrivateKey}  
        }
        else
        {
            $cert=get-item Cert:\CurrentUser\My\$Thumbprint
        }
    }
    return $cert

}

function CreateSelfSignedCertificate($Subject,$filepath)
{
    if ($PSVersionTable.Platform -eq "Unix")
    {
        $cert=CreateSelfSignedCertificateUnix -subject $Subject -addstore
    }
    else
    {
        $cert=New-SelfSignedCertificate -subject $Subject -CertStoreLocation "Cert:\CurrentUser\My" -KeySpec Signature -HashAlgorithm SHA256 -Provider "Microsoft Enhanced RSA and AES Cryptographic Provider"  -KeyExportPolicy NonExportable  -KeyLength 2048
        
    }
    if ($filepath) {
        $cert.Export("PKCS12",$filepath)
    }
    return $cert
}

function  CreateSelfSignedCertificateUnix($Subject,[switch] $addstore)
{
<#
    SubjectAlternativeNameBuilder sanBuilder = new-object System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder();
    sanBuilder.AddIpAddress(IPAddress.Loopback);
    sanBuilder.AddIpAddress(IPAddress.IPv6Loopback);
    sanBuilder.AddDnsName("localhost");
    sanBuilder.AddDnsName(Environment.MachineName);
#>
    $distinguishedName = new-object System.Security.Cryptography.X509Certificates.X500DistinguishedName($Subject)

    $rsa = [System.Security.Cryptography.RSA]::Create(2048)
    
    $request = new-object System.Security.Cryptography.X509Certificates.CertificateRequest($distinguishedName, $rsa, [System.Security.Cryptography.HashAlgorithmName]::SHA256,[System.Security.Cryptography.RSASignaturePadding]::Pkcs1);
    ##([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DataEncipherment -bor
    $ext = new-object System.Security.Cryptography.X509Certificates.X509KeyUsageExtension(([System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment -bor [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature ), $true)
    $request.CertificateExtensions.Add($ext) 
    $request.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509SubjectKeyIdentifierExtension]::new($request.PublicKey,$false))
    
    $oidcoll = new-object System.Security.Cryptography.OidCollection
    [void] $oidcoll.Add((new-object System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.1")))
    [void] $oidcoll.Add((new-object System.Security.Cryptography.Oid("1.3.6.1.5.5.7.3.2")))
    $ext2 = new-object System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension($oidcoll, $false)

    [void] $request.CertificateExtensions.Add($ext2)
        
    ## $request.CertificateExtensions.Add($sanBuilder.Build());

    $certificate= $request.CreateSelfSigned( (get-date).AddDays(-1),(get-date).AddDays(3650))
    
    ## store the cert if the store
    if ($addstore)
    {
        $storeName = [System.Security.Cryptography.X509Certificates.StoreName]::My
        $storeLocation = [System.Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
        $store = [System.Security.Cryptography.X509Certificates.X509Store]::new($storeName, $storeLocation)
        $store.Open("ReadWrite")
        $store.Add($certificate)
    }
    return $certificate
    ##return new X509Certificate2(certificate.Export(X509ContentType.Pfx, "WeNeedASaf3rPassword"), "WeNeedASaf3rPassword", X509KeyStorageFlags.MachineKeySet);
    
}

function Get-AADTenantDetails()
{
    
    if ($PSVersionTable.PSEdition -eq "Core")
    {
        $details = Get-AzADOrganization
        $details | add-member -NotePropertyName ObjectId -NotePropertyValue $details.id
        return $details
    }
    else
    {
        return Get-AzureADTenantDetails
    }
}

function select-ADtenantWin($tenantname)
{
	write-host "looking for tenant $tenantname .." -nonewline
    $conf.Tenants|?{$_.Name -eq $tenantname} |%{
        $tenant=$_
	    write-host "connecting to tenant $($tenant.tenantid)"
        while (!$tenant.TenantId) {
            $tenant | Add-Member -NotePropertyName TenantId   -NotePropertyValue (read-host "please enter the tenant id for $($tenant.Name)") -ErrorAction SilentlyContinue 
            
        }

        if ($tenant.AccessToken -and $tenant.Tenantid){
            $aadconn= Connect-AzureAD -TenantId $tenant.TenantId -AadAccessToken (DecryptWin $tenant.AccessToken) -accountid $tenant.accountid
        }else{
            ## try interactive 
            $aadconn= Connect-AzureAD -TenantId $tenant.TenantId
        }
        "TenantId","TenantDomain","AccessToken","AccountId"  | %{
                  $tenant  | Add-Member -NotePropertyName $_   -NotePropertyValue $null  -ErrorAction SilentlyContinue 
		}
		try {
	        get-azadtenantdetails -erroraction silentlycontinue | out-null
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
            $tenant.AccessToken = encryptwin -text (([Microsoft.Open.Azure.AD.CommonLibrary.AzureSession]::AccessTokens.Values[0].AccessToken))
            $conf | convertto-json | set-content $fullconfpath
            
        }

    }

}

function new-aadappcertcredential ($cert,$app)
{
    if ($PSVersionTable.PSEdition -eq "Core")
    {
        $secret=Get-AzADAppCredential -ObjectId $app.ObjectId | ?{$_.Type -eq "AsymmetricX509Cert"  -and $_.DisplayName -eq $cert.Subject -and [System.Convert]::ToBase64String( $_.CustomKeyIdentifier) -eq [System.Convert]::ToBase64String($cert.GetCertHash()) } | select -First 1
        if (!$secret) {
            write-host "could not find a credential for certificate $($cert.Subject) with $($cert.thumbprint) adding one"
            $null= New-AzADAppCredential -ObjectId $app.ObjectId -CustomKeyIdentifier ( [System.Convert]::ToBase64String( $cert.GetCertHash())) -CertValue ([System.convert]::ToBase64String($cert.RawData)) -StartDate (get-date).AddDays(-1) -EndDate $cert.NotAfter
            $secret=Get-AzADAppCredential -ObjectId $app.ObjectId | ?{$_.Type -eq "AsymmetricX509Cert"  -and $_.DisplayName -eq $cert.Subject -and [System.Convert]::ToBase64String( $_.CustomKeyIdentifier) -eq [System.Convert]::ToBase64String($cert.GetCertHash()) } | select -First 1
        }
    }
    else {
        $secret=New-AzureADApplicationKeyCredential -ObjectId $app.ObjectId -CustomKeyIdentifier ( [System.Convert]::ToBase64String( $cert.GetCertHash())) -Type AsymmetricX509Cert -Usage Verify -Value ([System.Convert]::ToBase64String( $cert.RawData)) -EndDate ($cert.NotAfter)
    }
    return $secret   
}

function CheckAppCredentials($app)
{
    if ($PSVersionTable.PSEdition -eq "Core")
    {
        return (Get-AzADAppCredential -ApplicationId $app.appid | ?{$_.keyid -eq $app.KeyId }) -ne $null 
    }
    else {
        return (Get-AzureADApplicationPasswordCredential -ObjectId $app.objectid | ?{$_.keyid -eq $app.KeyId }) -ne $null 
    }
}

function CleanAndCreateaadcredential($app)
{
    if ($PSVersionTable.PSEdition -eq "Core")
    {
        Get-AzADAppCredential -ApplicationId $app.appid |%{
            Remove-AzADAppCredential -ApplicationId $app.appid -KeyId $_.KeyId   | out-null
        }
        $secret=New-AzADAppCredential -ObjectId $app.ObjectId  
        
        if ($secret)
        {
            $app.KeyId = $secret.KeyId
            $app.KeyValue = Encrypt -text $secret.SecretText
        }   

    }
    else {
            ## remove existing secrets
            Get-AzureADApplicationPasswordCredential -ObjectId $app.objectid |%{
                Remove-AzureADApplicationPasswordCredential -ObjectId $app.objectid -KeyId $_.KeyId   | out-null
            }
    
            $secret=New-AzureADApplicationPasswordCredential -ObjectId $app.ObjectId 
            if ($secret)
            {
                $app.KeyId = $secret.KeyId        
                if ($PSVersionTable.Platform -ne "Unix")
                {
                    $app.KeyValue= (Encryptwin -text $secret.Value )
                }
            }   
            
    }   
}
function Set-AADApplication ($objectid , $AppRoles )
{
    
    if ($PSVersionTable.PSEdition -eq "Core")
    {
        ## first transform approles
        $appRole=$AppRoles |%{ 
            $o=[Microsoft.Azure.PowerShell.Cmdlets.Resources.MSGraph.Models.ApiV10.MicrosoftGraphAppRole]::new()  
            $o.AllowedMemberType = $_.AllowedMemberTypes ; $o.Description = $_.Description ; $o.DisplayName = $_.displayname
            $o.Id = $_.id ; $o.IsEnabled = $_.isenabled ;$o.Value = $_.Value 
            $o
        }
#        $appRole=$AppRoles |%{
#            $_ | add-member -NotePropertyName AllowedMemberType -NotePropertyValue $_.AllowedMemberTypes
#            $_.psobject.Properties.Remove("AllowedMemberTypes")
#            $_
#        }
        Set-AzADApplication -ObjectId $objectid -AppRole $AppRole
    }
    else{
        
        Set-AzureADApplication -ObjectId $objectid -AppRoles $AppRoles
    
    }
}

function retrieveorcreateapp($appdef,[switch]$multiTenant) {
    
    $app=Get-AADApp -appdef $appdef
    if (!$app) {
        $app=New-AADApp -Name $appdef.Name -multiTenant ([bool] $multiTenant)
        $app| Add-Member -NotePropertyName objectid -NotePropertyValue $app.Id
    }
    $appdef | Add-Member -NotePropertyName AppId  -NotePropertyValue $null -ErrorAction SilentlyContinue 

    "AppId","ObjectId","TenantId","App" |%{
        $appdef | Add-Member -NotePropertyName $_   -NotePropertyValue $null -ErrorAction SilentlyContinue 
    }

    $appdef.appid = $app.AppId
    $appdef.objectId = $app.ObjectId
    $appdef.tenantid =  (Get-AADTenantDetails).ObjectId

return $app
}

function Update-AADSPRoleAssignement($clientsp,$serversp,$AppRoleId)
{
    if ($PSVersionTable.PSEdition -eq "Core")
    {
        
        $ass= Get-AzADServicePrincipalAppRoleAssignment -ServicePrincipalId $clientsp.objectid
        if (!$ass){
                    
                $ass=New-AzADServicePrincipalAppRoleAssignment -ServicePrincipalId $clientsp.objectid  -ResourceId $serversp.objectid -AppRoleId $AppRoleId
        }
    }
    else
    {
        $ass = Get-AzureADServiceAppRoleAssignment -ObjectId $clientsp.ObjectId -All $true |?{$_.ResourceId -eq $serversp.objectId}
        if (!$ass){
	
            $ass=New-AzureADServiceAppRoleAssignment -objectid $clientsp.ObjectId -principalid $clientsp.ObjectId -resourceid $serversp.ObjectId -Id $AppRoleId
        }

    }
}



function New-AADServicePrincipal ($AppId) {
    if ($PSVersionTable.PSEdition -ne "Core") {
        $sp=New-AzureADServicePrincipal -ApplicationId $AppId
        
    }
    else {
        $sp=New-AzADServicePrincipal -ApplicationId $AppId
        $sp | Add-Member -NotePropertyName objectid -NotePropertyValue $sp.Id
    }
    return $sp
}

function Get-AADServicePrincipal($filter) {
    if ($PSVersionTable.PSEdition -eq "Core") 
    {
        $sp=Get-AzADServicePrincipal -Filter $filter
        $sp | Add-Member -NotePropertyName objectid -NotePropertyValue $sp.Id
        $sp | Add-Member -NotePropertyName AppRoles -NotePropertyValue $sp.AppRole
    }
    else {
        $sp=Get-AzureADServicePrincipal -Filter $filter
    }
    return $sp
}

function Set-AADServicePrincipal ($ObjectId, $AppRoleAssignmentRequired) {
    $p=@{}
    $p["ObjectId"]=$ObjectId

    if ($PSVersionTable.PSEdition -eq "Core") 
    {
        if ($AppRoleAssignmentRequired) {$p.Add("AppRoleAssignmentRequired",$null)}
        Set-AzADServicePrincipal @p
    }
    else {
        $p["AppRoleAssignmentRequired"]=$AppRoleAssignmentRequired
        Set-AzureADServicePrincipal @p
    }
}

function retrieveorcreatesp($appdef) {
    

    $sp= Get-AADServicePrincipal -Filter "AppId eq '$($serverappdef.AppId)'"
    if (!$sp){
        write-host "creating service principal for server application $($appdef.Name) [$($appdef.appid)]in tenant"
        $sp = New-AADServicePrincipal -AppId $appdef.AppId
        
    }
    Set-AADServicePrincipal -ObjectId $sp.objectid   -AppRoleAssignmentRequired $true
    $appdef | Add-Member -NotePropertyName TargetSPObjectId  -NotePropertyValue $sp.ObjectId -ErrorAction SilentlyContinue -force 
    write-host "target object sp for server is $($appdef.targetspobjectid)"

    return $sp
}


function Get-AADApp($appdef) {
    $app=$null
    if ($PSVersionTable.PSEdition -ne "Core"){
        if ($appdef.Appid )
        {
            $app=Get-AzureADApplication -Filter "AppId eq '$($appdef.AppId)'"    
        }
        if (! $app){
            $app=Get-AzureADApplication -Filter "DisplayName eq '$($appdef.Name)'"    
        }

    }
    else {
        if ($appdef.Appid ){
            $app=Get-AzADApplication -ApplicationId $appdef.AppId -ErrorAction SilentlyContinue
        }
        if (!$app){
            $app = Get-AzADApplication -DisplayName $appdef.Name
        }
        $app| Add-Member -NotePropertyName objectid -NotePropertyValue $app.Id
    }
    return $app
}

function New-AADApp  {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Name,
        [Parameter(Mandatory=$false)]
        [bool]$multiTenant

    )
    if ($PSVersionTable.Platform -ne "Unix"){
        $app=New-AzureADApplication -DisplayName $Name   -AvailableToOtherTenants $multiTenant
    }
    else {
        $app=New-AzADApplication -DisplayName $Name   -AvailableToOtherTenants $multiTenant
    }
    return $app
}


function CreateSecret($app) {
    "KeyId","KeyValue","CertificateThumbprint" |%{
        $app | Add-Member -NotePropertyName $_   -NotePropertyValue $null -ErrorAction SilentlyContinue
    }
    if ($app.credentialtype -eq "Certificate" )
    {
        if (  $app.CertificateThumbprint)
	    {   
            $cert=GetCertificateFromStore -thumbprint $app.CertificateThumbprint
            write-host "checkinf if certificate $($app.certificatethumbprint) is present in store"

            if (!$cert) { 
                write-host "certificate not found locally " 
                $app.CertificateThumbprint = $null 
            }
            else {
                write-host "certificate found locally " 
                
            }
        }

        if (-not $app.CertificateThumbprint) {
            if ($PSVersionTable.Platform -ne "Unix") {
                foreach ($cert in  (dir Cert:\CurrentUser\my |?{$_.subject -eq $app.Name -and !$_.HasPrivateKey}) ){
                    remove-item $_ -Force -Confirm:$false
                }
            }
            $cert = GetCertificateFromStore -name "CN=$($app.Name)" | select -First 1
                
            if (!$cert ) {
                write-host "creating cert with Microsoft Enhanced RSA and AES Cryptographic Provider"
                $cert=CreateSelfSignedCertificate -subject "CN=$($app.Name)"
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
        }
        $secret=new-aadappcertcredential -app $app -cert $cert
        if ($secret) {
            $app.CertificateThumbprint = $cert.Thumbprint
            $app.KeyId = $secret.KeyId
        }
    }
    
    if ($app.credentialtype -eq "Password" -and  $app.KeyId -and $app.keyvalue)
    {
        write-host "checking we can decrypt the password for $($app.KeyId) for app $($app.Name)[$($app.AppId)in config file]"
        try{
            Decrypt -blob $app.KeyValue
        }catch {
            write-host "could not decrypt content, need to generate a new secret"
            $key.keyvalue = $null
        }
        if (! (CheckAppCredentials -app $app))
        {
            $app.KeyId = $null
            $app.keyvalue=$null
        }

    }
    if ($app.credentialtype -eq "Password" -and (-not $app.KeyId -or -not $app.keyvalue)) {
        
        CleanAndCreateaadcredential -app $app        

    }
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
        "TenantId","TenantDomain","AccessToken","AccountId","AccessTokenExpiration"  | %{
            if (-not $tenant.$_) { $tenant  | Add-Member -NotePropertyName $_   -NotePropertyValue $null  -ErrorAction SilentlyContinue }
        }
        $aadconn=Connect-AAD -tenant $tenant


        if ($aadconn)
        {

            $conf | convertto-json | set-content $fullconfpath
            
        }

    }

}

Load-Credentials $conf
$conf | convertto-json | set-content $fullconfpath

##Select-ADtenant-2 -tenantname Client
