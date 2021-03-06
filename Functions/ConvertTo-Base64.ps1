
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

