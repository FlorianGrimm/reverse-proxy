# createcerts.ps1

# 1

$cert1 = New-SelfSignedCertificate -Type Custom -DnsName "localhost" -KeySpec Signature `
    -Subject "CN=localhost client 1" -KeyExportPolicy Exportable `
    -HashAlgorithm sha256 -KeyLength 2048 `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") `
    -NotAfter ([System.DateTime]::new(2082, 2, 2))

$sspassword1 = ConvertTo-SecureString "testPassword1" -AsPlainText -Force

Export-PfxCertificate -Cert $cert1 -FilePath localhostclient1.pfx -Password $sspassword1

Export-Certificate -FilePath "localhostclient1.cer" -Cert $cert1 -Type CERT

# 2

$cert2 = New-SelfSignedCertificate -Type Custom -DnsName "localhost2" -KeySpec Signature `
    -Subject "CN=localhost client 2" -KeyExportPolicy Exportable `
    -HashAlgorithm sha256 -KeyLength 2048 `
    -CertStoreLocation "Cert:\CurrentUser\My" `
    -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.2") `
    -NotAfter ([System.DateTime]::new(2082, 2, 2))

$sspassword2 = ConvertTo-SecureString "testPassword2" -AsPlainText -Force

Export-PfxCertificate -Cert $cert2 -FilePath localhostclient2.pfx -Password $sspassword2

Export-Certificate -FilePath "localhostclient2.cer" -Cert $cert2 -Type CERT

#

<# #>
[string] $FullName = (dir '.\localhostclient1.cer').FullName
$cert1 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($FullName)

[string] $FullName = (dir '.\localhostclient1.pfx').FullName
$cert1 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($FullName, 'testPassword1', [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::PersistKeySet)

$cert1.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pkcs12, 'testPassword1')
'.\localhostclient1.p12'

$cert1 | gm

#$cert1.PublicKey.Oid.Value

<# #>
