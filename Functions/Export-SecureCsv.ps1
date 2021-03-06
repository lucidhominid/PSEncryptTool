
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

