<#
# remove the certificates from Cert:/CurrentUser/My
#>
[string]$clientLocalhost2023FriendlyName = "yarp-client-localhost-2023"
$clientLocalhost2023Certificate = Get-ChildItem Cert:/CurrentUser/My | Where-Object {$_.FriendlyName -eq $clientLocalhost2023FriendlyName}
if ($null -ne $clientLocalhost2023Certificate) {
    $clientLocalhost2023Certificate | Remove-Item
}

[string]$clientLocalhost2024FriendlyName = "yarp-client-localhost-2024"
$clientLocalhost2024Certificate = Get-ChildItem Cert:/CurrentUser/My | Where-Object {$_.FriendlyName -eq $clientLocalhost2024FriendlyName}
if ($null -ne $clientLocalhost2024Certificate) {
    $clientLocalhost2024Certificate | Remove-Item
}

[string]$clientLocalhost2025FriendlyName = "yarp-client-localhost-2025"
$clientLocalhost2025Certificate = Get-ChildItem Cert:/CurrentUser/My | Where-Object {$_.FriendlyName -eq $clientLocalhost2025FriendlyName}
if ($null -ne $clientLocalhost2025Certificate) {
    $clientLocalhost2025Certificate | Remove-Item
}

[string]$clientLocalhost2026FriendlyName = "yarp-client-localhost-2026"
$clientLocalhost2026Certificate = Get-ChildItem Cert:/CurrentUser/My | Where-Object {$_.FriendlyName -eq $clientLocalhost2026FriendlyName}
if ($null -ne $clientLocalhost2026Certificate) {
    $clientLocalhost2026Certificate | Remove-Item
}


$rootFriendlyName = "yarp-root-ca"
$rootCertificate = Get-ChildItem Cert:/CurrentUser/My | Where-Object {$_.FriendlyName -eq $rootFriendlyName}
if ($null -ne $rootCertificate) {
    $rootCertificate | Remove-Item
}
$rootCertificate = Get-ChildItem Cert:/CurrentUser/Root | Where-Object {$_.FriendlyName -eq $rootFriendlyName}
if ($null -ne $rootCertificate) {
    $rootCertificate | Remove-Item
}
