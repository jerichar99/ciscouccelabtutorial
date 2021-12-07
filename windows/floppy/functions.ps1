function Sleep-Countdown ($seconds, $msg) {  For ($i=$seconds; $i -gt 0; $i--) { Write-Progress -Activity $msg -SecondsRemaining $i; Start-Sleep 1 } }

# Export-CertFile -site "cvp-a.jlab1.local:8111" -fileName "cvp-a_8111.cer", outputs base64 .cer/.pem
function Export-CertFile ([string]$site, [string]$fileName) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 # need on Win2016 server?
    Write-Host "Creating $fileName for $site";
    # code based on https://stackoverflow.com/questions/22233702/how-to-download-the-ssl-certificate-from-a-website-using-powershell/22236908
    $webRequest = [Net.WebRequest]::Create("https://" + $site);
    $webRequest.Timeout = 5000;
    try { $webRequest.GetResponse() > $null; } catch {}
    $cert = $webRequest.ServicePoint.Certificate;
    $cert_der = $cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert); # der is in binary
    $cert_b64 = [System.Convert]::ToBase64String($cert_der); # convert to base64, single line
    # add line breaks every 64 characters
    for ($i = 64; $i -lt $cert_b64.Length; $i+=66) {
        $cert_b64 = $cert_b64.Insert($i, "`r`n");
    }
    $cert_b64 = "-----BEGIN CERTIFICATE-----`r`n" + $cert_b64 + "`r`n-----END CERTIFICATE-----";

    set-content -value $cert_b64 -encoding ascii -path "$fileName";
}

function Import-CertFile ([string]$alias, [string]$fileName) {
	Write-Host "Importing $fileName";
    $isCVP = ($env:CVP_HOME -ne $null); # cvp or cce
    $storePass = if ($isCVP) { (Get-Content "$($env:CVP_HOME)\conf\security.properties").Substring(22) } else { "changeit" }; # cvp=password is dynamic (grab it out the file), if cce=changeit
    if ($isCVP) {
        . "$($env:CVP_HOME)\jre\bin\keytool.exe" -storetype JCEKS -keystore "$($env:CVP_HOME)\conf\security\.keystore" -import -storepass $storePass -alias $alias -file $fileName -noprompt 2> $null; }
    else {
        . "$($env:JAVA_HOME)\bin\keytool.exe" -keystore "$($env:JAVA_HOME)\lib\security\cacerts" -import -storepass $storePass -alias $alias -file $fileName -noprompt 2> $null;
    }
}

function Download-Install { param($url, $argumentList)
    $fileName = $url.Substring($url.LastIndexOf('/')+1); # turn https://test.com/test.exe => test.exe
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;
    Invoke-WebRequest "$url" -OutFile "$($env:TEMP)\$fileName"; 
    Start-Process -FilePath "$($env:TEMP)\$fileName" -argumentList "$argumentList" -Verb RunAs -Wait;
};

function Set-ChromeAsDefaultBrowser {
    Add-Type -AssemblyName 'System.Windows.Forms';
    Start-Process $env:windir\system32\control.exe -ArgumentList '/name Microsoft.DefaultPrograms /page pageDefaultProgram\pageAdvancedSettings?pszAppName=google%20chrome';
    Sleep 5;
    [System.Windows.Forms.SendKeys]::SendWait("{TAB} {TAB}{TAB} ");
}

function Customize-Explorer {
    Write-Host "Customize-Explorer called";
    REG ADD HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v AlwaysShowMenus /t REG_DWORD /d 1 /f > $null # explorer: always show menus
    REG ADD HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v TaskbarGlomLevel /t REG_DWORD /d 2 /f > $null # taskbar: 2=never combine taskbar buttons
    REG ADD HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\CabinetState /v FullPath /t REG_DWORD /d 1 /f > $null # explorer: display full path in the title bar
    REG ADD HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v Hidden /t REG_DWORD /d 1 /f > $null # explorer: show hidden files (1=show, 2=hide)
    REG ADD HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v ShowSuperHidden /t REG_DWORD /d 1 /f > $null # explorer: show protected operating system files
    REG ADD HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideDrivesWithNoMedia /t REG_DWORD /d 0 /f > $null # explorer: 0=show empty drives
    REG ADD HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideFileExt /t REG_DWORD /d 0 /f > $null # explorer: 0=show file extensions
    REG ADD HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced /v HideMergeConflicts /t REG_DWORD /d 1 /f > $null # explorer: 1=hide folder merge conflicts
    REG ADD HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\StuckRects3 /v Settings /t REG_BINARY /d "30000000feffffff02020000010000003e0000002800000000000000fb02000000040000230300006000000001000000" /f > $null # set taskbar to top ( ...0202000001... is top, ...0202000003... is bottom)

	# restart explorer for changes to take effect
	Stop-Process -ProcessName explorer -Force > $null;
	c:\windows\explorer.exe > $null;
	Sleep 5;
}

function Install-CommonPrograms {
    Write-Host 'Installing Chrome...';
    Download-Install -url "http://dl.google.com/chrome/install/375.126/chrome_installer.exe" -argumentList "/silent /install";
	Set-ChromeAsDefaultBrowser
    Write-Host 'Installing Notepad++...'
    # latest is from https://notepad-plus-plus.org/update/getDownloadUrl.php
    Download-Install -url "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v8.1.2/npp.8.1.2.Installer.exe" -argumentList "/S";
    Write-Host 'Installing 7zip...'
    Download-Install -url "https://www.7-zip.org/a/7z1900-x64.exe" -argumentList "/S";
    Write-Host "Installing telnet client...";
    Install-WindowsFeature -name Telnet-Client > $null;
}

