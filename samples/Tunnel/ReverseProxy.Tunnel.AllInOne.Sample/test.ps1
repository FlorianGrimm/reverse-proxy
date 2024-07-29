$e=[System.IO.Path]::GetFullPath("$PSScriptRoot\..\..\..\artifacts\bin\ReverseProxy.Tunnel.AllInOne.Sample\Debug\net8.0\ReverseProxy.Tunnel.AllInOne.Sample.exe")
Write-Host $e
function run($m, $a){
    Write-Host "---------------------------------------------"
    Write-Host "$m $a test stop"
    Write-Host "---------------------------------------------"
    . $e $m $a test stop
    if (0 -ne $LastExitCode) {
        Write-Host "Failed to test $m $a test stop"
        exit 1
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
# # # run "ws-a" "browser-windows"
run "ws-c" "browser-anonymous"
# # run "ws-c" "browser-windows"
# # run "ws-w" "browser-anonymous"
# # run "ws-w" "browser-windows"
# run "h2ws-a" "browser-anonymous"
# run "h2ws-a" "browser-windows"
# run "h2ws-w" "browser-anonymous"
# run "h2ws-w" "browser-windows"

