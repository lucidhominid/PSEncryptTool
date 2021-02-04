Function Encrypt-String {
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
        ConvertFrom-SecureString -SecureString $secureString -Key $bytes|ConvertTo-Base64
    }elseif("$Scope")
    {
        $StringBytes=$String|ConvertTo-Byte
        [System.Security.Cryptography.ProtectedData]::Protect($StringBytes,$null,$Scope)|ConvertTo-Base64
    }
    }
    }
Function Decrypt-String {
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
        Encrypt-String |
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
    Get-Content -Path $Path | Decrypt-String |
        ConvertFrom-Csv
}
}