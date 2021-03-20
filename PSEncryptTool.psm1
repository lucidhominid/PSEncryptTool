Add-Type -AssemblyName System.Security

Get-ChildItem $PSScriptRoot -Filter *.cs|
    ForEach-Object{
        $_ | Add-type -ReferencedAssemblies System.Drawing, System.Windows.Forms
    }

Get-ChildItem $PSScriptRoot\Functions -filter *.ps1 | 
    ForEach-Object {
        $ThisFunctionName = $_.Name -replace '\.ps1'
        $ThisFunction = [Scriptblock]::Create(
            "Function $ThisFunctionName {$((Get-Content $_.FullName) -join "`n")}"
        )
        .$ThisFunction
        ($ThisFunction.ast.EndBlock.statements.body.beginblock.Statements| 
            Where-Object {
                $_.condition.extent.text -like "`$PSCmdlet.MyInvocation.InvocationName"
            }).Clauses.Item1.Value|
            Where-Object {$_ -ne $null}|
            ForEach-Object{
                try{
                    New-Alias -Name $_ -Value $ThisFunctionName -ErrorAction Stop
                }catch{
                    Write-Verbose "Alias '$_' with value '$ThisFunctionName' could not being exported."
                }
            }
    }