<#
# create certificates in Cert:/CurrentUser/My and export it to folder
#>
[string] $dest = [System.IO.Path]::GetDirectoryName($PSScriptRoot)
Write-Host "Destination folder: $dest"

[System.DateTime] $dt2000_01_01=[System.DateTime]::new(2000, 1, 1)
[System.DateTime] $dt2023_01_01=[System.DateTime]::new(2023, 1, 1)
[System.DateTime] $dt2024_01_01=[System.DateTime]::new(2024, 1, 1)
[System.DateTime] $dt2024_02_01=[System.DateTime]::new(2024, 2, 1)
[System.DateTime] $dt2025_01_01=[System.DateTime]::new(2025, 1, 1)
[System.DateTime] $dt2025_02_01=[System.DateTime]::new(2025, 2, 1)
[System.DateTime] $dt2026_01_01=[System.DateTime]::new(2026, 1, 1)
[System.DateTime] $dt2026_02_01=[System.DateTime]::new(2026, 2, 1)
[System.DateTime] $dt2100_01_01=[System.DateTime]::new(2100, 1, 1)

[System.Security.SecureString]$pwd = ConvertTo-SecureString -String "testPassword" -Force -AsPlainText

<# yarp-root-ca #>

$rootFriendlyName = "yarp-root-ca"

$rootCertificate = Get-ChildItem Cert:/CurrentUser/My | Where-Object {$_.FriendlyName -eq $rootFriendlyName}
if ($null -eq $rootCertificate) {
    $rootCertificate = New-SelfSignedCertificate `
        -DnsName "localhost" `
        -CertStoreLocation "cert:\CurrentUser\My" `
        -NotBefore $dt2000_01_01 `
        -NotAfter $dt2100_01_01 `
        -Subject "CN=$rootFriendlyName" `
        -FriendlyName $rootFriendlyName `
        -KeyExportPolicy Exportable `
        -KeyUsageProperty All `
        -KeyUsage CertSign, CRLSign, DigitalSignature
}
Export-PfxCertificate -Cert $rootCertificate -FilePath ([System.IO.Path]::Combine($dest, "$($rootFriendlyName).pfx")) -Password $pwd
Export-Certificate -Cert $rootCertificate -FilePath ([System.IO.Path]::Combine($dest, "$($rootFriendlyName).crt"))

Import-Certificate -FilePath ([System.IO.Path]::Combine($dest, "$($rootFriendlyName).crt")) -CertStoreLocation cert:/CurrentUser/Root

<# yarp-client-localhost-2023 #>

[string]$clientLocalhost2023FriendlyName = "yarp-client-localhost-2023"
$clientLocalhost2023Certificate = Get-ChildItem Cert:/CurrentUser/My | Where-Object {$_.FriendlyName -eq $clientLocalhost2023FriendlyName}
if ($null -eq $clientLocalhost2023Certificate) {
    $clientLocalhost2023Certificate = New-SelfSignedCertificate -Type Custom `
        -DnsName "localhost" `
        -NotBefore $dt2023_01_01 `
        -NotAfter $dt2024_02_01 `
        -Subject "CN=$clientLocalhost2023FriendlyName" `
        -FriendlyName $clientLocalhost2023FriendlyName `
        -KeySpec Signature `
        -KeyExportPolicy Exportable `
        -HashAlgorithm sha256 `
        -KeyLength 2048 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -Signer $rootCertificate `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")
}
Export-PfxCertificate -Cert $clientLocalhost2023Certificate -FilePath ([System.IO.Path]::Combine($dest, "$($clientLocalhost2023FriendlyName).pfx")) -Password $pwd
Export-Certificate -Cert $clientLocalhost2023Certificate -FilePath ([System.IO.Path]::Combine($dest, "$($clientLocalhost2023FriendlyName).crt"))


<# yarp-client-localhost-2024 #>

[string]$clientLocalhost2024FriendlyName = "yarp-client-localhost-2024"
$clientLocalhost2024Certificate = Get-ChildItem Cert:/CurrentUser/My | Where-Object {$_.FriendlyName -eq $clientLocalhost2024FriendlyName}
if ($null -eq $clientLocalhost2024Certificate) {
    $clientLocalhost2024Certificate = New-SelfSignedCertificate -Type Custom `
        -DnsName "localhost" `
        -NotBefore $dt2024_01_01 `
        -NotAfter $dt2025_02_01 `
        -Subject "CN=$clientLocalhost2024FriendlyName" `
        -FriendlyName $clientLocalhost2024FriendlyName `
        -KeySpec Signature `
        -KeyExportPolicy Exportable `
        -HashAlgorithm sha256 `
        -KeyLength 2048 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -Signer $rootCertificate `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")
}
Export-PfxCertificate -Cert $clientLocalhost2024Certificate -FilePath ([System.IO.Path]::Combine($dest, "$($clientLocalhost2024FriendlyName).pfx")) -Password $pwd
Export-Certificate -Cert $clientLocalhost2024Certificate -FilePath ([System.IO.Path]::Combine($dest, "$($clientLocalhost2024FriendlyName).crt"))


<# yarp-client-localhost-2025 #>

[string]$clientLocalhost2025FriendlyName = "yarp-client-localhost-2025"
$clientLocalhost2025Certificate = Get-ChildItem Cert:/CurrentUser/My | Where-Object {$_.FriendlyName -eq $clientLocalhost2025FriendlyName}
if ($null -eq $clientLocalhost2025Certificate) {
    $clientLocalhost2025Certificate = New-SelfSignedCertificate -Type Custom `
        -DnsName "localhost" `
        -NotBefore $dt2025_01_01 `
        -NotAfter $dt2026_02_01 `
        -Subject "CN=$clientLocalhost2025FriendlyName" `
        -FriendlyName $clientLocalhost2025FriendlyName `
        -KeySpec Signature `
        -KeyExportPolicy Exportable `
        -HashAlgorithm sha256 `
        -KeyLength 2048 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -Signer $rootCertificate `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")
}
Export-PfxCertificate -Cert $clientLocalhost2025Certificate -FilePath ([System.IO.Path]::Combine($dest, "$($clientLocalhost2025FriendlyName).pfx")) -Password $pwd
Export-Certificate -Cert $clientLocalhost2025Certificate -FilePath ([System.IO.Path]::Combine($dest, "$($clientLocalhost2025FriendlyName).crt"))


<# yarp-client-localhost-2026 #>

[string]$clientLocalhost2026FriendlyName = "yarp-client-localhost-2026"
$clientLocalhost2026Certificate = Get-ChildItem Cert:/CurrentUser/My | Where-Object {$_.FriendlyName -eq $clientLocalhost2026FriendlyName}
if ($null -eq $clientLocalhost2026Certificate) {
    $clientLocalhost2026Certificate = New-SelfSignedCertificate -Type Custom `
        -DnsName "localhost" `
        -NotBefore $dt2026_01_01 `
        -NotAfter $dt2100_01_01 `
        -Subject "CN=$clientLocalhost2026FriendlyName" `
        -FriendlyName $clientLocalhost2026FriendlyName `
        -KeySpec Signature `
        -KeyExportPolicy Exportable `
        -HashAlgorithm sha256 `
        -KeyLength 2048 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -Signer $rootCertificate `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2")
}
Export-PfxCertificate -Cert $clientLocalhost2026Certificate -FilePath ([System.IO.Path]::Combine($dest, "$($clientLocalhost2026FriendlyName).pfx")) -Password $pwd
Export-Certificate -Cert $clientLocalhost2026Certificate -FilePath ([System.IO.Path]::Combine($dest, "$($clientLocalhost2026FriendlyName).crt"))

