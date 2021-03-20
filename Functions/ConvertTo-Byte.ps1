
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

