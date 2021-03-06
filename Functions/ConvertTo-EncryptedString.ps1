
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

