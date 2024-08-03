cd $PSScriptRoot
[System.Environment]::CurrentDirectory = $PSScriptRoot

dotnet build

dir .\LogFiles\ | Remove-Item

$e=[System.IO.Path]::GetFullPath("$PSScriptRoot\..\..\..\artifacts\bin\ReverseProxy.Tunnel.AllInOne.Sample\Debug\net8.0\ReverseProxy.Tunnel.AllInOne.Sample.exe")
Write-Host $e

$success=[System.Collections.ArrayList]::new()
$failed=[System.Collections.ArrayList]::new()

$stopOnError = $false

function run($m, $a){
    Write-Host "---------------------------------------------"
    Write-Host "$m $a test stop"
    Write-Host "---------------------------------------------"
    . $e $m $a test stop
    if (0 -ne $LastExitCode) {
        Write-Host "Failed to test $m $a test stop"
        if ($stopOnError){
            exit 1
        } else{
            $failed.Add("$m $a")
        }
    } else {
        $success.Add("$m $a")
    }
}

run "h2-a" "browser-anonymous"
run "h2-a" "browser-windows"
run "h2-c" "browser-anonymous"
run "h2-c" "browser-windows"
run "h2-w" "browser-anonymous"
run "h2-w" "browser-windows"
run "h2-j" "browser-anonymous"
run "h2-j" "browser-windows"
run "ws-a" "browser-anonymous"
run "ws-a" "browser-windows" #
run "ws-c" "browser-anonymous"
run "ws-c" "browser-windows"
run "ws-w" "browser-anonymous"
run "ws-w" "browser-windows"
run "h2ws-a" "browser-anonymous"
run "h2ws-a" "browser-windows"
run "h2ws-w" "browser-anonymous"
run "h2ws-w" "browser-windows"

Write-Host "---------------------------------------------"
Write-Host "Success"
Write-Host "---------------------------------------------"

$success | %{ Write-Host $_}

Write-Host "---------------------------------------------"
Write-Host "Failed"
Write-Host "---------------------------------------------"

$failed | %{ Write-Host $_}
if (0 -eq $failed.Count){exit 0}else{exit 1}

