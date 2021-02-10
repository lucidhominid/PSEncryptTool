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
        #Create a Byte[]; an array to hold our bytes
        $OutObject  = [Byte[]]::new(0)
    }
    Process{
        Switch($InputObject){
            {#If input is Byte
                $_ -is [Byte]
            }{#Then add it to OutObject
                $OutObject += $InputObject
            }
            {#If input is String
                $_ -is [String]
            }{#Then convert it to a Byte[] and add each Byte to OutObject
                $InputObject |
                    ConvertTo-Byte |
                    ForEach-Object{
                        $OutObject += $_
                    }
            }
        }
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
        #Parameter: InputString
        [Parameter(
            ValuefromPipeLine
        )][String[]]
        $InputString
    )
    Process{
        #Yeah, it just does this...
        [Convert]::FromBase64String($InputString)
    }
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
    #Parameter: InputObject
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
        #Parameter: 
        [Parameter(
            Mandatory,
            Position=0,
            ValueFromPipeline
        )][String[]]
        $InputString,
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
    Begin{
        if(
            $Key
        ){
            $length = $Key.length
            <#if(
                ($length -lt 16) -or ($length -gt 32)
            ){
                Throw [Exception]::new(
                    'Key must be between 16 and 32 characters',
                    'Invalid key length.'
                )
            }#>
            $Encoding = New-Object System.Text.ASCIIEncoding
            $Bytes    = $Encoding.GetBytes(
                $Key + "0" * (32 - $length)
            )
        }
    }
    Process{
        if($Key){
            if($InputString -is [System.Security.SecureString]){
                $Securestring = $InputString
            }else{
                $Securestring = new-object System.Security.SecureString
                $InputString.toCharArray() |
                    ForEach-Object{
                        $secureString.AppendChar($_)
                    }
            }
            $SecureString |
                ConvertFrom-SecureString -Key $bytes
        }elseif(
            "$Scope"
        ){
            [System.Security.Cryptography.ProtectedData]::Protect(
                ($InputString | ConvertTo-Byte),
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
        $InputString,

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
            <#if(
                ($length -lt 16) -or ($length -gt 32)
            ){
                Throw "Key must be between 16 and 32 characters"
            }#>
            Try{
                $KeyBytes = $Key + "0" * $Pad|ConvertTo-Byte
                $InputString | 
                    ConvertTo-SecureString -key $KeyBytes -ErrorAction Stop |
                    ForEach-Object {
                        [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                            [Runtime.InteropServices.Marshal]::SecureStringToBSTR(
                                $_
                            )
                        )
                    }
            }Catch{
                $ErrorType = $_.Exception.GetType()
                Switch($_.Exception.Message)
                {
                    'Padding is invalid and cannot be removed.' {
                        $ThrowMessage = 'The provided key is invalid.'
                    }
                    "The parameter value `"$InputString`" is not a valid encrypted string." {
                        $ThrowMessage = "`"$InputString`" is not a valid encrypted string."
                    }
                }
                Write-Error -Exception $ErrorType::new($ThrowMessage) -TargetObject $Key -ErrorAction Stop
            }
            
        }else{
            [System.Security.Cryptography.ProtectedData]::Unprotect(
                ($InputString | ConvertFrom-Base64),
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
        $InputObject | 
            ForEach-Object{
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
            }catch{
                Throw $_.Exception
            }
        })][String]
        $Path
    )
    Process{
        [System.BitConverter]::ToString(
            [System.Security.Cryptography.MD5CryptoServiceProvider]::new().ComputeHash($(
                if(
                    #Note: It seems that $InputObject is seen as an [Array] here. Indexing into the first item in the array resolves this.
                    $Path -or $InputObject[0] -is [System.IO.FileInfo]
                ){
                    $Path, 
                    $InputObject |
                        Where-Object {
                            $_
                        } |
                        Select-Object -First 1 |
                        Get-Item |
                        Get-Content -Encoding Byte -Raw
                }elseif($InputObject -is [Byte[]]){
                    $InputObject
                }else {
                    [System.Text.UTF8Encoding]::UTF8.GetBytes(
                        $InputObject
                    )
                }
            ))
        ).tolower() -replace '-'
    }
}
$MyInvocation.MyCommand.ScriptBlock.Ast.EndBlock.Statements | 
    ForEach-Object {
        Export-ModuleMember -Function $_.Name
    }