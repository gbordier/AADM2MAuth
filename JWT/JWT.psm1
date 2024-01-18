## JWT module
function translateJWTMembers {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline = $true)]
        $token
    )
    
    $token | Get-Member -MemberType NoteProperty | ForEach-Object {
        $name = $_.Name
        
        switch ($name) {
            "exp" { 
                $token.$name = ([DateTime]"1/1/1970").AddSeconds( $token.$name).ToLocalTime()
            }
            "iat" { 
                $token.$name = ([DateTime]"1/1/1970").AddSeconds( $token.$name).ToLocalTime()
            }
            "nbf" { 
                $token.$name = ([DateTime]"1/1/1970").AddSeconds( $token.$name).ToLocalTime()
            }
                
            Default { }
        }
        
    }

    return $token
    
}


function decode-header( [parameter(ValueFromPipeline = $true)] [string] $header) {
    $header = $header | ConvertFrom-Json
    return $header
    
}

function decode-payload( [parameter(ValueFromPipeline = $true)] [string] $payload) {
    
    $deodedpayload = $payload | ConvertFrom-Json | translateJWTMembers
    return $deodedpayload
    
}

function Invoke-Base64UrlDecode {
    <#
        .SYNOPSIS
        .DESCRIPTION
        .NOTES
            http://blog.securevideo.com/2013/06/04/implementing-json-web-tokens-in-net-with-a-base-64-url-encoded-key/
            Author:  yvind Kallstad
            Date: 23.03.2015
            Version: 1.0
    #>
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline = $true)]
        [string] $Argument
    )
    
    $output = $Argument.Replace('-', '+')
    $output = $output.Replace('_', '/')
    $modulus = $output.Length % 4
    if ($modulus -gt 0 ) { $modulus = 4 - $modulus }
    for ($i = 0 ; $i -lt $modulus ; $i++) { $output = $output + '=' }
    $output = [System.Convert]::FromBase64String($output)
    return $output
    
}

function EncodeBase64UrlString{
   [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline = $true)]
        [string] $Argument
    )
	$output = [System.Convert]::ToBase64String( [System.Text.Encoding]::ASCII.GetBytes( $Argument))
	$output = $output.Replace('+', '-')
	$output = $output.Replace('/','_')
	$output = $output.Replace("=","")

	return Output
}

function DecodeBase64UrlToString {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0, Mandatory, ValueFromPipeline = $true)]
        [string] $Argument
    )
    $blob = Invoke-Base64UrlDecode -Argument $Argument
    $output = [System.Text.Encoding]::ASCII.GetString($blob)
    return $output
}

function Decode-Token([parameter(ValueFromPipeline = $true)] $token, [ValidateSet("access_token","id_token")] $token_type = "access_token") 
{
    $tokens = $token.Split('.') 
    $header = $tokens[0] | DecodeBase64UrlToString | decode-header 
    $payload = $tokens[1] | DecodeBase64UrlToString | decode-payload
    
    #    write-verbose "header : $header"
    #   write-verbose "payload : $payload"
    return New-Object -TypeName pscustomobject -Property  @{type  = "access_token"
        header     = $header
        payload    = $payload
        token_type = $token_type

    } 
}



function Decode-JWT ([parameter(ValueFromPipeline = $true)] $token, [ValidateSet("access_token","id_token")] $token_type = "access_token") {
    if ($token -is [pscustomobject])
    {
        if ($token.access_token) {}
        if ($token.Refresh_token) {}
        if ($token.Id_token) {}

    }
    else { Decode-Token -token $token }
}



##Export-ModuleMember -Function Decode-JWT