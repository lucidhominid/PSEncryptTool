Add-Type -AssemblyName System.Security
Function ConvertFrom-Decimal{
    [CmdletBinding()]
    Param
    (
        [Parameter(ValuefromPipeLine)]
        $InputObject,
        [Int]$Base=2
    )
        [System.Convert]::ToString($InputObject,$Base)
    
    }
    Function ConvertTo-Decimal{
    [CmdletBinding()]
    Param
    (
        [Parameter(ValuefromPipeLine)]
        $InputObject,
        [Int]$Base=2
    )
        [Convert]::ToInt64($InputObject,$Base)
    
    }
    Function ConvertTo-Base64{
    [CmdletBinding()]
    Param
    (
        [Parameter(ValuefromPipeLine)]
        $InputObject
    )
    Begin
    {
        $OutObject = @()
    }
    Process
    {
        $OutObject+=$InputObject
        
    }
    End
    {
        [Convert]::ToBase64String($OutObject)
    }
    }
    Function ConvertFrom-Base64{
    [CmdletBinding()]
    Param
    (
        [Parameter(ValuefromPipeLine)]
        $InputObject
    )
        [Convert]::FromBase64String($InputObject)
    }
    Function ConvertTo-Byte{
    [CmdletBinding()]
    Param
    (
        [Parameter(ValuefromPipeLine)]
        $InputObject
    )
    
    Process
    {
        ($InputObject -join "`n").ToCharArray()|ForEach-Object{[Byte]$_}
    }
    }
    Function ConvertTo-String{
    [CmdletBinding()]
    Param
    (
        [Parameter(ValuefromPipeLine)]
        $InputObject
    )
    Begin
    {
        $OutObject = @()
    }
    Process
    {
        $OutObject+=$InputObject
    }
    End
    {
        ($OutObject|ForEach-Object{[Char]$_})-join ''
    }
    }
Function ConvertTo-EncryptedString {
    [CmdletBinding(DefaultParameterSetName="Scope")]
    param
    (
        [Parameter(Mandatory,Position=0,ValueFromPipeline)]
        $String,
        [Parameter(ParameterSetName='Key',Mandatory,Position=1)]
        [String]$Key,
        [Parameter(ParameterSetName='Scope',Position=1)]
        [ValidateSet("CurrentUser","LocalMachine")]
        [System.Security.Cryptography.DataProtectionScope]$Scope = "CurrentUser"
    )
    Begin
    {
        Add-Type -AssemblyName System.Security
        $Encoding = New-Object System.Text.ASCIIEncoding
        $Bytes = $Encoding.GetBytes($Key + "0" * $pad)
    }
    Process
    {
    if($Key)
    {
        if($String -is [System.Security.SecureString])
        {
            $Securestring = $String
        }
        else
        {
            $Securestring = new-object System.Security.SecureString
            $Chars = $String.toCharArray()
            foreach($Char in $Chars)
            {
                $secureString.AppendChar($char)
            }
        }
        $length = $Key.length
        $pad    = 32 - $length
        if (($length -lt 16) -or ($length -gt 32))
        {
            Throw "Key must be between 16 and 32 characters"
        }
    
        <#[PSCustomObject]@{
            EncryptedData = ConvertFrom-SecureString -SecureString $secureString -Key $bytes
            Key           = $Key
        }#>
        ConvertFrom-SecureString -SecureString $secureString -Key $bytes | ConvertTo-Base64
    }elseif("$Scope")
    {
        $StringBytes=$String|ConvertTo-Byte
        [System.Security.Cryptography.ProtectedData]::Protect($StringBytes,$null,$Scope)|ConvertTo-Base64
    }
    }
    }
Function ConvertFrom-EncryptedString {
    [CmdletBinding(DefaultParameterSetName="Scope")]
    param
    (
        [Parameter(Mandatory,Position=0,ValueFromPipeline)]
        $String,
        [Parameter(ParameterSetName='Key',Mandatory,Position=1)]
        [String]$Key,
        [Parameter(ParameterSetName='Scope',Position=1)]
        [ValidateSet("CurrentUser","LocalMachine")]
        [System.Security.Cryptography.DataProtectionScope]$Scope = "CurrentUser"
    )
    Begin
    {
        Add-Type -AssemblyName System.Security
    }
    Process
    {
    if($key)
    {
        $length = $Key.length
        $pad    = 32 - $length
        if(($length -lt 16) -or ($length -gt 32)){
            Throw "Key must be between 16 and 32 characters"
        }
        $Encoding = New-Object System.Text.ASCIIEncoding
        $key  = $Encoding.GetBytes(
            $Key + "0" * $pad
        )
        $Data = $String | 
            ConvertTo-Byte
        $data | ConvertTo-SecureString -key $key |
                ForEach-Object{
                    [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($_)
                    )
                }
    }
    else
    {
        [System.Security.Cryptography.ProtectedData]::Unprotect(
            ($String|ConvertFrom-Base64),$null,$Scope
        ) | ConvertTo-String
    }
    }
    }
Function Export-SecureCsv {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [String]
        $Path,
        [Parameter(ValueFromPipeline)]
        [Object[]]
        $InputObject
    )
Begin{
    $Entries = @()
}
Process{
    $InputObject | ForEach-Object{
        $Entries += $_
    }
}
End{
    $Entries | ConvertTo-Csv |
        ConvertTo-EncryptedString |
            Out-File -FilePath $Path
}
}
Function Import-SecureCsv {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,ValueFromPipeline)]
        [String]
        $Path
    )
Process{
    Get-Content -Path $Path | ConvertFrom-EncryptedString |
        ConvertFrom-Csv
}
}

Export-ModuleMember -Function ConvertFrom-Base64
Export-ModuleMember -Function ConvertFrom-Decimal
Export-ModuleMember -Function ConvertTo-Base64
Export-ModuleMember -Function ConvertTo-Byte
Export-ModuleMember -Function ConvertTo-Decimal
Export-ModuleMember -Function ConvertTo-Object
Export-ModuleMember -Function ConvertTo-String
Export-ModuleMember -Function ConvertFrom-EncryptedString
Export-ModuleMember -Function ConvertTo-EncryptedString
Export-ModuleMember -Function Export-SecureCsv
Export-ModuleMember -Function Import-SecureCsv