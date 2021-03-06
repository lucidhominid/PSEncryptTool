
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

