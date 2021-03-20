
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

