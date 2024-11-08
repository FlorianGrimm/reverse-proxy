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

run "h2-anonymous" "browser-anonymous"
run "h2-anonymous" "browser-negotiate"
run "h2-certificate" "browser-anonymous"
run "h2-certificate" "browser-negotiate"
run "h2-negotiate" "browser-anonymous"
run "h2-negotiate" "browser-negotiate"
run "h2-jwtbearer" "browser-anonymous"
run "h2-jwtbearer" "browser-negotiate"
run "ws-anonymous" "browser-anonymous"
run "ws-anonymous" "browser-negotiate" #
run "ws-certificate" "browser-anonymous"
run "ws-certificate" "browser-negotiate"
run "ws-negotiate" "browser-anonymous"
run "ws-negotiate" "browser-negotiate"
run "h2ws-anonymous" "browser-anonymous"
run "h2ws-anonymous" "browser-negotiate"
run "h2ws-negotiate" "browser-anonymous"
run "h2ws-negotiate" "browser-negotiate"

Write-Host "---------------------------------------------"
Write-Host "Success"
Write-Host "---------------------------------------------"

$success | %{ Write-Host $_}

Write-Host "---------------------------------------------"
Write-Host "Failed"
Write-Host "---------------------------------------------"

$failed | %{ Write-Host $_}
if (0 -eq $failed.Count){exit 0}else{exit 1}

