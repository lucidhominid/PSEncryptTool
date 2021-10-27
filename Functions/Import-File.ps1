[CmdletBinding()]
Param(
    [Parameter(
        Position = 0,
        ValueFromPipeline
    )][ValidateScript({
        Try{
            $_ | Get-Item
        }Catch{
            Throw $_.Exception
        }
    })][String[]]
    $Path = $(
        Add-Type -AssemblyName System.Windows.Forms
        $FileBrowser = [System.Windows.Forms.OpenFileDialog]@{
            InitialDirectory = Get-Location
        }
        [Void]$FileBrowser.ShowDialog()
        $FileBrowser.FileName
    ),

    [Parameter(
        Position = 1
    )][ValidateSet(
        'CSV','TXT','XML','JSON','BMP','Byte'
    )][String]
    $Type
)
Process{
    $Path |
        ForEach-Object{
            $ProcessHash = @{
                CSV   = {Import-Csv $_}
                TXT   = {Get-Content $_}
                XML   = {Import-Clixml $_}
                JSON  = {ConvertFrom-Json (Get-Content $_)}
                BMP   = {New-Object System.Drawing.Bitmap($_)}
                Byte  = {[System.IO.File]::ReadAllBytes($_)}
            }

            If(!$Type){
                $Type = $_.Split('.')[-1]
            }

            try{
                &$ProcessHash.$Type
            }catch{
                if($_.Exception -like "*The Expression After '&'*"){
                    Throw 'Invalid file extension. Please specify file type with -Type.'
                }else{
                    Throw $_
                }
            }
        }
}