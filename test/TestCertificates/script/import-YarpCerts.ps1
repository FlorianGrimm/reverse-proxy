<#
# import the certificates from folder to Cert:/CurrentUser/My
#>
[string] $dest = [System.IO.Path]::GetDirectoryName($PSScriptRoot)
Write-Host "Destination folder: $dest"

[System.Security.SecureString]$pwd = ConvertTo-SecureString -String "testPassword" -Force -AsPlainText

$rootFriendlyName = "yarp-root-ca"
$rootCertificate = Get-ChildItem Cert:/CurrentUser/Root | Where-Object {$_.FriendlyName -eq $rootFriendlyName}
if ($null -eq $rootCertificate) {
    Import-PfxCertificate -Exportable -Password $pwd -FilePath ([System.IO.Path]::Combine($dest, "$($rootFriendlyName).pfx")) -CertStoreLocation cert:/CurrentUser/Root
}

[string]$clientLocalhost2023FriendlyName = "yarp-client-localhost-2023"
$clientLocalhost2023Certificate = Get-ChildItem Cert:/CurrentUser/My | Where-Object {$_.FriendlyName -eq $clientLocalhost2023FriendlyName}
if ($null -eq $clientLocalhost2023Certificate) {
    Import-PfxCertificate -Exportable -Password $pwd -FilePath ([System.IO.Path]::Combine($dest, "$($clientLocalhost2023FriendlyName).pfx")) -CertStoreLocation cert:/CurrentUser/My
}

[string]$clientLocalhost2024FriendlyName = "yarp-client-localhost-2024"
$clientLocalhost2024Certificate = Get-ChildItem Cert:/CurrentUser/My | Where-Object {$_.FriendlyName -eq $clientLocalhost2024FriendlyName}
if ($null -eq $clientLocalhost2024Certificate) {
    Import-PfxCertificate -Exportable -Password $pwd -FilePath ([System.IO.Path]::Combine($dest, "$($clientLocalhost2024FriendlyName).pfx")) -CertStoreLocation cert:/CurrentUser/My
}

[string]$clientLocalhost2025FriendlyName = "yarp-client-localhost-2025"
$clientLocalhost2025Certificate = Get-ChildItem Cert:/CurrentUser/My | Where-Object {$_.FriendlyName -eq $clientLocalhost2025FriendlyName}
if ($null -eq $clientLocalhost2025Certificate) {
    Import-PfxCertificate -Exportable -Password $pwd -FilePath ([System.IO.Path]::Combine($dest, "$($clientLocalhost2025FriendlyName).pfx")) -CertStoreLocation cert:/CurrentUser/My
}

[string]$clientLocalhost2026FriendlyName = "yarp-client-localhost-2026"
$clientLocalhost2026Certificate = Get-ChildItem Cert:/CurrentUser/My | Where-Object {$_.FriendlyName -eq $clientLocalhost2026FriendlyName}
if ($null -eq $clientLocalhost2026Certificate) {
    Import-PfxCertificate -Exportable -Password $pwd -FilePath ([System.IO.Path]::Combine($dest, "$($clientLocalhost2026FriendlyName).pfx")) -CertStoreLocation cert:/CurrentUser/My
}
