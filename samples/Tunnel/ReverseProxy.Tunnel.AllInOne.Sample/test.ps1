$e=[System.IO.Path]::GetFullPath("$PSScriptRoot\..\..\..\artifacts\bin\ReverseProxy.Tunnel.AllInOne.Sample\Debug\net8.0\ReverseProxy.Tunnel.AllInOne.Sample.exe")
Write-Host $e
function run($m){
    Write-Host "$m browser-anonymous test stop"
    . $e $m browser-anonymous test stop
    if (0 -ne $LastExitCode) {
        Write-Host "Failed to test $m browser-anonymous test stop"
        exit 1
    }
    Write-Host "$m browser-windows test stop"
    . $e $m browser-windows test stop
    if (0 -ne $LastExitCode) {
        Write-Host "Failed to test $m browser-windows test stop"
        exit 1
    }
}
run "h2-a"
run "h2-c"
run "h2-w"
run "h2-j"
run "h2ws-a"
run "h2ws-w"
run "ws-a"
run "ws-c"
run "ws-w"

