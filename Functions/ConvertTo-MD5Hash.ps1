
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

