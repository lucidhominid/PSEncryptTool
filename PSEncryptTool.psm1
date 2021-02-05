Add-Type -AssemblyName System.Security
Function ConvertTo-Base64{
    [CmdletBinding()]
    Param(
        #Parameter: InputObject
        [Parameter(
            ValuefromPipeLine
        )][Object]
        $InputObject
    )
    Begin{
        $OutObject  = @()
    }
    Process{
        $OutObject += $InputObject
    }
    End{
        [Convert]::ToBase64String(
            $OutObject
        )
    }
}
Function ConvertFrom-Base64{
    [CmdletBinding()]
    Param(
        [Parameter(
            ValuefromPipeLine
        )][String[]]
        $InputObject
    )
    [Convert]::FromBase64String($InputObject)
}
Function ConvertTo-Byte{
    [CmdletBinding()]
    Param(
        [Parameter(
            ValuefromPipeLine
        )][String[]]
        $InputObject
    )
    Process{
        ($InputObject -join "`n").ToCharArray() |
            ForEach-Object{
                [Byte]$_
            }
    }
}
Function ConvertTo-String{
[CmdletBinding()]
Param(
    #Parameter: Byte
    [Parameter(
        ValuefromPipeLine
    )][Byte]
    $InputObject
)
Begin{
    $OutObject  = @()
}
Process{
    $OutObject += $InputObject
}
End{
    $OutObject |
        ForEach-Object {
            [Char]$_
        } |
        Join-String
}
}
Function ConvertTo-EncryptedString {
    [CmdletBinding(
        DefaultParameterSetName="Scope"
    )]
    Param(
        [Parameter(
            Mandatory,
            Position=0,
            ValueFromPipeline
        )][String[]]
        $String,
        [Parameter(
            ParameterSetName = 'Key',
            Mandatory,
            Position=1
        )][String]
        $Key,
        [Parameter(
            ParameterSetName = 'Scope',
            Position = 1
        )][ValidateSet(
            "CurrentUser",
            "LocalMachine"
        )][System.Security.Cryptography.DataProtectionScope]
        $Scope = "CurrentUser"
    )
    Begin{
        if(
            $Key
        ){
            $length = $Key.length
            if(
                ($length -lt 16) -or ($length -gt 32)
            ){
                Throw [Exception]::new(
                    'Key must be between 16 and 32 characters',
                    'Invalid key length.'
                )
            }
            $Encoding = New-Object System.Text.ASCIIEncoding
            $Bytes    = $Encoding.GetBytes(
                $Key + "0" * (32 - $length)
            )
        }
    }
    Process{
        if(
            $Key
        ){
            if(
                $String -is [System.Security.SecureString]
            ){
                $Securestring = $String
            }else{
                $Securestring = new-object System.Security.SecureString
                $Chars = $String.toCharArray()
                foreach($Char in $Chars){
                    $secureString.AppendChar($char)
                }
            }
            ConvertFrom-SecureString -SecureString $secureString -Key $bytes | 
                ConvertTo-Base64
        }elseif(
            "$Scope"
        ){
            [System.Security.Cryptography.ProtectedData]::Protect(
                ($String | ConvertTo-Byte),
                $null,
                $Scope
            ) | ConvertTo-Base64
        }
    }
}
Function ConvertFrom-EncryptedString{
    [CmdletBinding(
        DefaultParameterSetName = "Scope"
    )]
    Param(
        #Parameter: String
        [Parameter(
            Mandatory,
            Position = 0,
            ValueFromPipeline
        )][String]
        $String,

        #Parameter: Key
        [Parameter(
            ParameterSetName = 'Key',
            Mandatory,
            Position = 1
        )][String]
        $Key,

        #Parameter: Scope
        [Parameter(
            ParameterSetName = 'Scope',
            Position = 1
        )][ValidateSet(
            "CurrentUser",
            "LocalMachine"
        )][System.Security.Cryptography.DataProtectionScope]
        $Scope = "CurrentUser"
    )
    Process{
        if(
            $Key
        ){
            $length = $Key.length
            $Pad    = 32 - $length
            if(
                ($length -lt 16) -or ($length -gt 32)
            ){
                Throw "Key must be between 16 and 32 characters"
            }
            $Key = [System.Text.ASCIIEncoding]::ASCII.GetBytes(
                $Key + "0" * $Pad
            )
            $String | 
                ConvertTo-Byte | 
                ConvertTo-SecureString -key $key |
                ForEach-Object {
                    [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                        [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
                            $_
                        )
                    )
                }
        }else{
            [System.Security.Cryptography.ProtectedData]::Unprotect(
                ($String | ConvertFrom-Base64),
                $null,
                $Scope
            ) | ConvertTo-String
        }
    }
}
Function Export-SecureCsv {
    [CmdletBinding()]
    Param(
        #Parameter: Path
        [Parameter(
            Mandatory
        )][String]
        $Path,
        #Parameter: InputObject
        [Parameter(
            Mandatory,
            ValueFromPipeline
        )][Object[]]
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
        $Entries | 
            ConvertTo-Csv | 
            Out-String |
            ConvertTo-EncryptedString |
            Out-File -FilePath $Path
    }
}
Function Import-SecureCsv {
    [CmdletBinding()]
    Param(
        #Parameter: Path
        [Parameter(
            Mandatory,
            ValueFromPipeline
        )][String]
        $Path
    )
    Process{
        $Path |
            Resolve-Path | 
            Get-Content | 
            ConvertFrom-EncryptedString |
            Out-String |
            ConvertFrom-Csv
    }
}
Function ConvertTo-MD5Hash{
    [CmdletBinding(
        DefaultParameterSetName = 'InputObject'
    )]
    Param (
        #Parameter: InputObject
        [Parameter(
            ParameterSetName = 'InputObject',
            ValueFromPipeline,
            Mandatory
        )][Object[]]
        $InputObject,
        #Parameter: Path
        [Parameter(
            ParameterSetName = 'Path',
            Mandatory
        )][ValidateScript({
            try {
                $_ | Get-Item -ErrorAction Stop
            }catch {
                Throw $_.Exception
            }
        })][String]
        $Path
    )
    Process{
        [System.BitConverter]::ToString(
            [System.Security.Cryptography.MD5CryptoServiceProvider]::new().ComputeHash(
                $(
                    if(
                        $Path -or $InputObject -is [System.IO.FileInfo]
                    ){
                        $Path, 
                        $InputObject |
                            Where-Object {
                                $_
                            } |
                            Get-Item |
                            Get-Content -Encoding Byte -Raw
                    }else{
                        [System.Text.UTF8Encoding]::UTF8.GetBytes(
                            $InputObject
                        )
                    }
                )
            )
        ).tolower() -replace '-'
    }
}
'ConvertFrom-Base64',
'ConvertTo-Base64',
'ConvertTo-Byte',
'ConvertTo-Object',
'ConvertTo-String',
'ConvertFrom-EncryptedString',
'ConvertTo-EncryptedString',
'Export-SecureCsv',
'Import-SecureCsv',
'ConvertTo-MD5Hash' | 
    ForEach-Object {
        Export-ModuleMember -Function $_
    }