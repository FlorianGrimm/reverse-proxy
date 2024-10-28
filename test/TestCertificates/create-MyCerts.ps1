
<# https://learn.microsoft.com/en-us/azure/vpn-gateway/vpn-gateway-certificates-point-to-site #>
<# https://gist.github.com/RomelSan/bea2443684aa0883b117c37bac1de520 #>

$certRoot = Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -eq 'CN=MyRootCert'}
if ($null -eq $certRoot) {
    $params = @{
        Type = 'Custom'
        Subject = 'CN=MyRootCert'
        KeySpec = 'Signature'
        KeyExportPolicy = 'Exportable'
        KeyUsage = 'CertSign'
        KeyUsageProperty = 'Sign'
        KeyLength = 2048
        HashAlgorithm = 'sha256'
        NotAfter = (Get-Date).AddMonths(24)
        CertStoreLocation = 'Cert:\CurrentUser\My'
    }
    $certRoot = New-SelfSignedCertificate @params
    $sspasswordRoot = ConvertTo-SecureString "rootPassword1" -AsPlainText -Force
    Export-PfxCertificate -Cert $certRoot -FilePath myroot.pfx -Password $sspasswordRoot
    Export-Certificate -FilePath "myroot.cer" -Cert $certRoot -Type CERT
}

# Manually Import the myroot.pfx

$certMyLocalHostClient2023 = Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -eq 'CN=my localhost client 2023'}
if ($null -eq $certMyLocalHostClient2023) {

    $certMyLocalHostClient2023 = New-SelfSignedCertificate -Type Custom `
        -DnsName "localhost" `
        -KeySpec Signature `
        -Subject "CN=my localhost client 2023" -KeyExportPolicy Exportable `
        -HashAlgorithm sha256 -KeyLength 2048 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") `
        -NotBefore ([System.DateTime]::new(2023, 1, 1)) `
        -NotAfter ([System.DateTime]::new(2024, 1, 31)) `
        -Signer $certRoot

    $sspassword2023 = ConvertTo-SecureString "testPassword2023" -AsPlainText -Force
    Export-PfxCertificate -Cert $certMyLocalHostClient2023 -FilePath "mylocalhostclient2023.pfx" -Password $sspassword2023
    Export-Certificate -FilePath "mylocalhostclient2023.cer" -Cert $certMyLocalHostClient2023 -Type CERT


    $certMyLocalHostClient2024 = New-SelfSignedCertificate -Type Custom `
        -DnsName "localhost" `
        -KeySpec Signature `
        -Subject "CN=my localhost client 2024" -KeyExportPolicy Exportable `
        -HashAlgorithm sha256 -KeyLength 2048 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") `
        -NotBefore ([System.DateTime]::new(2024, 1, 1)) `
        -NotAfter ([System.DateTime]::new(2025, 1, 31)) `
        -Signer $certRoot

    $sspassword2024 = ConvertTo-SecureString "testPassword2024" -AsPlainText -Force
    Export-PfxCertificate -Cert $certMyLocalHostClient2024 -FilePath "mylocalhostclient2024.pfx" -Password $sspassword2024
    Export-Certificate -FilePath "mylocalhostclient2024.cer" -Cert $certMyLocalHostClient2024 -Type CERT

    $certMyLocalHostClient2025 = New-SelfSignedCertificate -Type Custom `
        -DnsName "localhost" `
        -KeySpec Signature `
        -Subject "CN=my localhost client 2025" -KeyExportPolicy Exportable `
        -HashAlgorithm sha256 -KeyLength 2048 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") `
        -NotBefore ([System.DateTime]::new(2025, 1, 1)) `
        -NotAfter ([System.DateTime]::new(2026, 1, 31)) `
        -Signer $certRoot

    $sspassword2025 = ConvertTo-SecureString "testPassword2025" -AsPlainText -Force
    Export-PfxCertificate -Cert $certMyLocalHostClient2025 -FilePath "mylocalhostclient2025.pfx" -Password $sspassword2025
    Export-Certificate -FilePath "mylocalhostclient2025.cer" -Cert $certMyLocalHostClient2025 -Type CERT
}

####

$certMyJwt2023 = Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -eq 'CN=my jwt sign for localhost'} | Where-Object {$_.NotBefore -eq ([System.DateTime]::new(2023, 1, 1))}
if ($null -eq $certMyJwt2023) {
    $certMyJwt2023 = New-SelfSignedCertificate -Type Custom `
        -KeySpec Signature `
        -KeyUsage DigitalSignature `
        -FriendlyName "my jwt sign for localhost 2023"  `
        -Subject "CN=my jwt sign for localhost" -KeyExportPolicy Exportable `
        -HashAlgorithm sha256 -KeyLength 2048 `
        -CertStoreLocation "Cert:\CurrentUser\My" `
        -NotBefore ([System.DateTime]::new(2023, 1, 1)) `
        -NotAfter ([System.DateTime]::new(2024, 1, 31)) `
        -Signer $certRoot

    $sspassword2023 = ConvertTo-SecureString "testPassword2023" -AsPlainText -Force
    Export-PfxCertificate -Cert $certMyJwt2023 -FilePath "myJwt2023.pfx" -Password $sspassword2023
    Export-Certificate -FilePath "myJwt2023.cer" -Cert $certMyJwt2023 -Type CERT
}

$certMyJwt2024 = Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -eq 'CN=my jwt sign for localhost'} | Where-Object {$_.NotBefore -eq ([System.DateTime]::new(2024, 1, 1))}
if ($null -eq $certMyJwt2024){
    $certMyJwt2024 = New-SelfSignedCertificate -CloneCert $certMyJwt2023 `
    -NotBefore ([System.DateTime]::new(2024, 1, 1)) `
    -NotAfter ([System.DateTime]::new(2025, 1, 31)) `
    -FriendlyName "my jwt sign for localhost 2024"  `
    -Signer $certRoot

    $sspassword2024 = ConvertTo-SecureString "testPassword2024" -AsPlainText -Force
    Export-PfxCertificate -Cert $certMyJwt2024 -FilePath "myJwt2024.pfx" -Password $sspassword2024
    Export-Certificate -FilePath "myJwt2024.cer" -Cert $certMyJwt2024 -Type CERT
    Import-PfxCertificate -Exportable -Password $sspassword2024 -CertStoreLocation "Cert:\CurrentUser\My" -FilePath "myJwt2024.pfx"
}


$certMyJwt2025 = Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -eq 'CN=my jwt sign for localhost'} | Where-Object {$_.NotBefore -eq ([System.DateTime]::new(2025, 1, 1))}
if ($null -eq $certMyJwt2025){

    $certMyJwt2025 = New-SelfSignedCertificate -CloneCert $certMyJwt2024 `
        -NotBefore ([System.DateTime]::new(2025, 1, 1)) `
        -NotAfter ([System.DateTime]::new(2026, 1, 31)) `
        -FriendlyName "my jwt sign for localhost 2025"  `
        -Signer $certRoot

    $sspassword2025 = ConvertTo-SecureString "testPassword2025" -AsPlainText -Force
    Export-PfxCertificate -Cert $certMyJwt2025 -FilePath "myJwt2025.pfx" -Password $sspassword2025
    Export-Certificate -FilePath "myJwt2025.cer" -Cert $certMyJwt2025 -Type CERT
    Import-PfxCertificate -Exportable -Password $sspassword2025 -CertStoreLocation "Cert:\CurrentUser\My" -FilePath "myJwt2025.pfx"

}

Get-ChildItem Cert:\CurrentUser\My | Where-Object {$_.Subject -eq 'CN=my jwt sign for localhost'} | fl
