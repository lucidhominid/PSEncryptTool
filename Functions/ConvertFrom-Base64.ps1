
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

