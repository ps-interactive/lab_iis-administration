<#Administer IIS Pluralsight IT Ops Cloud Lab
Questions? Contact the author, Tim Warner, at
timothy-warner@pluralsight.com #>

# Import the relevant PowerShell modules
Import-Module -Name WebAdministration
Import-Module -Name PKI

# Create the application pool
New-WebAppPool -Name CorpSitePool

# Create the website folder
New-Item -ItemType Directory -Path C:\inetpub\CorpSite

# Create the new website
New-Website -Name CorpSite -PhysicalPath C:\inetpub\CorpSite -Port 8080 -ApplicationPool CorpSitePool

# Populate the content folder
$corpSitePath = (Get-Website -Name "CorpSite").PhysicalPath

# Create index.html content
$htmlContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Administer IIS Lab</title>
</head>
<body>
    <h1>Welcome to Pluralsight!</h1>
    <hr>
</body>
</html>
"@

# Write the content to index.html in the CorpSite directory
Set-Content -Path (Join-Path -Path $corpSitePath -ChildPath "index.html") -Value $htmlContent

# Set the application pool recycling time (every 24 hours @ 2:30am)
$applicationPoolName = "CorpSitePool"

# Get the application pool configuration path
$appPoolPath = "IIS:\AppPools\$applicationPoolName"

# Clear existing schedule (if any)
Clear-ItemProperty -Path $appPoolPath -Name recycling.periodicRestart.schedule

# Set the time-based recycling at 2:30 AM
New-ItemProperty -Path $appPoolPath -Name recycling.periodicRestart.schedule -Value @{value = '02:30:00'}

# Create a new self-signed certificate
$cert = New-SelfSignedCertificate -DnsName "ps-win-1" -CertStoreLocation "cert:\LocalMachine\My" -FriendlyName "ps-web" -NotAfter (Get-Date).AddYears(1) -KeySpec KeyExchange -KeyUsage DigitalSignature, KeyEncipherment -TextExtension @("2.5.29.37={text}1.3.6.1.5.5.7.3.1")

# Add the certificate to the Trusted Root Certification Authorities store
Export-Certificate -Cert $cert -FilePath "ps-win-1.cer"
Import-Certificate -FilePath "ps-win-1.cer" -CertStoreLocation "cert:\LocalMachine\Root"
Remove-Item -Path "ps-win-1.cer"

# Export the certificate as a PFX package
$password = ConvertTo-SecureString -String "Pa$$w0rd1" -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath "ps-win-1.pfx" -Password $password

# Get the certificate thumbprint
$thumbprint = (Get-ChildItem -Path "cert:\LocalMachine\My" | Where-Object { $_.Subject -match "ps-win-1" }).Thumbprint

# Bind the certificate to the website
New-WebBinding -Name CorpSite -Protocol https -Port 443 -SslFlags 0 -HostHeader "ps-win-1"
$binding = Get-WebBinding -Name CorpSite -Protocol https
$binding.AddSslCertificate($thumbprint, "my")

# Test access
Start-Process -FilePath msedge -ArgumentList https://ps-win-1

# Create test user account
$password = ConvertTo-SecureString "1abcdefgH-2" -AsPlainText -Force
$user = New-LocalUser -Name "test" -FullName "Test User" -Password $password -Description "Test User Account"
Add-LocalGroupMember -Group "Users" -Member $user

# Disable anonymous authentication
Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/anonymousAuthentication" -Name "enabled" -Value "False" -Location $siteName -PSPath 'IIS:\'

# Configure Basic authentication
Import-Module -Name IISAdministration
Install-WindowsFeature -Name Web-Basic-Auth

$siteName = "CorpSite"
Set-WebConfigurationProperty -Filter "/system.webServer/security/authentication/basicAuthentication" -Name "enabled" -Value "True" -Location $siteName -PSPath 'IIS:\'

$webConfigContent = @"
<configuration>
  <system.web>
    <authorization>
      <allow roles="BUILTIN\Users" />
      <deny users="?" />
    </authorization>
  </system.web>
</configuration>
"@

$webConfigPath = (Get-WebSite -Name $siteName).physicalPath + "\web.config"
Set-Content -Path $webConfigPath -Value $webConfigContent

# Reset anonymous authentiction
$websiteName = "CorpSite"
Set-WebConfigurationProperty -Filter "system.webServer/security/authentication/basicAuthentication" -Name "enabled" -Value $false -PSPath "IIS:\"
Set-WebConfigurationProperty -Filter "system.webServer/security/authentication/anonymousAuthentication" -Name "enabled" -Value $true -PSPath "IIS:\"

# Back up IIS server configuration
Backup-WebConfiguration -Name "iiscfg1"

# Verify backup was created
Explorer.exe C:\Windows\System32\inetsrv\backup

# Back up website content
$allWebsites = Get-Website
$backupRoot = "C:\Backup"

foreach ($singleWebsite in $allWebsites) {
  $siteName = $singleWebsite.Name
  $siteContentPath = [Environment]::ExpandEnvironmentVariables($singleWebsite.PhysicalPath)
  $siteBackupPath = Join-Path -Path $backupRoot -ChildPath $siteName

  # Create the backup folder for the website
  New-Item -Path $siteBackupPath -ItemType Directory -Force

  # Copy the website content to the backup folder
  Copy-Item -Path $siteContentPath -Destination $siteBackupPath -Recurse -Force
}

# Set the log level to Debug
Set-WebConfigurationProperty -Filter "system.webServer/httpLogging" -Name dontLog -Value False -Location CorpSite

# Generate synthetic traffic
for ($i = 1; $i -le 100; $i++) {
  Invoke-WebRequest -Uri "https://ps-win-1" -UseBasicParsing
}

# Get the log folder path
$logFolderPath = Join-Path -Path $env:SystemDrive -ChildPath "inetpub\logs\LogFiles"

# Get the most recent log folder
$recentLogFolder = Get-ChildItem -Path $logFolderPath | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1

# Get the most recent log file in the folder
$recentLogFile = Get-ChildItem -Path $recentLogFolder.FullName | Sort-Object -Property LastWriteTime -Descending | Select-Object -First 1

# Parse the log file
$logData = Get-Content -Path $recentLogFile.FullName | ConvertFrom-Csv -Delimiter " " -Header Date, Time, ServerIP, Method, UriStem, UriQuery, Port, Username, ClientIP, UserAgent, Referrer, HttpStatusCode, SubStatus, Win32Status, BytesSent, BytesReceived, TimeTaken

# Analyze the log data
$logData | Group-Object -Property HttpStatusCode | Sort-Object -Property Count -Descending
