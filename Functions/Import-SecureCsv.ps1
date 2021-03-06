
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

