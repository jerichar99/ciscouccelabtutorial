function VM-SecondsSinceLastReboot ($vmName) { (Get-Stat -Entity $vmName -Stat 'sys.osuptime.latest' -MaxSamples 1).Value } 
function Sleep-Countdown ($seconds, $msg) {  For ($i=$seconds; $i -gt 0; $i--) { Write-Progress -Activity $msg -SecondsRemaining $i; Start-Sleep 1 } }

# sends keyboard presses into the VM, using a complicated mapping of characters to USB HID scan codes
# note: not exhaustive mapping, more characters can be added
# Send-VMKeystrokesText -vmName "ROUTER.JLAB1.LOCAL" -txt "myPassword" will type "m y P a s s w o r d" into the VM session
# Special characters: <tab>, <enter>, <X> (sleep X seconds), <left> arrow left, <up>, <down>, <right>, <del>, <win> (windows left key)
# modified from https://williamlam.com/2017/09/automating-vm-keystrokes-using-the-vsphere-api-powercli.html
function Send-VMKeystrokesText { param($vmName, [string]$txt, [string]$description)
    $vmGV = Get-View -ViewType VirtualMachine -Filter @{"Name" = $vmName };
    if ($description -ne $null) { Write-Host $description; }

    $hidCodesEvents = @();
    $chars = $txt.ToCharArray();
    # loop through each character in $txt
    for ($i = 0; $i -le $chars.Length ; $i++) {
        $hidCode = 0;
        $shift = $control = $alt = $win = $false;

        # special commands like <tab>, <enter>, <5> (5 second sleep) etc.
        if ($chars[$i] -eq '<') {
            $cmd = "";
            while ($chars[++$i] -ne '>') { # accumulate characters until >
                $cmd = $cmd + $chars[$i];
            }
            # if it's a number like <2>, then we need to dump $hidCodesEvents, clear array, sleep X seconds, and continue on
            if ($cmd -match "^\d+$") {
                $seconds = [int]$cmd;
                if ($hidCodesEvents.Count -gt 0) {
                    $spec = New-Object Vmware.Vim.UsbScanCodeSpec -Property @{ KeyEvents = $hidCodesEvents};
                    $vmGV.PutUsbScanCodes($spec) > $null;
                }
                $hidCodesEvents = @(); # clear it out
                # if 6+ seconds, use sleep countdown, otherwise just sleep
                if ($seconds -gt 5) { Sleep-Countdown -msg "Sleeping $seconds seconds" -seconds $seconds; }
                else { Sleep -Seconds $seconds; }
                continue;
            } # sleep and go back to for loop top
            elseif ($cmd -match "[%^+#][a-z]") { # alt, ctrl, shift, win, like <^v> for paste, <#r> for win+r
                switch ($cmd[0]) { "%" { $alt = $true; } "^" { $control = $true; } "+" { $shift = $true; } "#" { $win = $true; } }
                $hidCode = [byte][char]$cmd[1] - 93; # a=4, b=5...z=29
            }
            else {
                $hidCode = switch ($cmd) { "tab" { 43 } "enter" { 40 } "right" { 79 } "left" { 80 } "down" { 81 } "up" { 82 } "del" { 76 } "win" { 227 } }
            }
        }
        else {
            $char = $chars[$i];
            $asciiCode = [byte][char]$char;

            if ($asciiCode -ge ([byte][char]'a') -and $asciiCode -le ([byte][char]'z')) { # a-z
                $hidCode = [byte][char]$char - 93; # a=4, b=5...z=29
            } elseif ($asciiCode -ge ([byte][char]'A') -and $asciiCode -le ([byte][char]'Z')) { # A-Z
                $hidCode = [byte][char]$char - 61; # same codes as a-z, but with shift
                $shift = $true;
            } elseif ($asciiCode -ge ([byte][char]'1') -and $asciiCode -le ([byte][char]'9')) { # 1-9
                $hidCode = [byte][char]$char - 19; # 1=30, 2=31...9=38
            }
            else { # no pattern with these characters, just a lookup table (some with shifts)
                $hidCode = switch ($char) { '"' { $shift = $true; 52 } '''' { 52 } '~' { $shift = $true; 53 } '|' { $shift = $true; 49 } ' ' { 44 } '0' { 39 } '!' { $shift = $true; 30 } '@' { $shift = $true; 31 } '#' { $shift = $true; 32 } '$' { $shift = $true; 33 } '%' { $shift = $true; 34 } '^' { $shift = $true; 35 } '&' { $shift = $true; 36 } '*' { $shift = $true; 37 } '(' { $shift = $true; 38 } ')' { $shift = $true; 39 } '_' { $shift = $true; 45 } '+' { $shift = $true; 46 } '\' { 49 } '-' { 45 } '.' { 55 } '/' { 56 } ':' { $shift = $true; 51 } ';' { 51 } '<' { $shift = $true; 54 } '<' { $shift = $true; 55 } '?' { $shift = $true; 56 } '[' { 47 } ']' { 48 } '{' { $shift=$true; 47 } '}' { $shift=$true; 48 }   }
            }
        }

        $tmp = New-Object VMware.Vim.UsbScanCodeSpecKeyEvent -Property @{ UsbHidCode = ($hidCode -shl 16) -bor 0007 };
        $tmp.Modifiers = (New-Object Vmware.Vim.UsbScanCodeSpecModifierType -Property @{ LeftAlt = $alt; LeftShift = $shift; LeftControl = $control; LeftGui = $win; });
        $hidCodesEvents += $tmp;
    }

    # key in remaining codes
    if ($hidCodesEvents.Count -gt 0) {
        $spec = New-Object Vmware.Vim.UsbScanCodeSpec -Property @{ KeyEvents = $hidCodesEvents};
        $vmGV.PutUsbScanCodes($spec) > $null;
    }
}

# Install-WindowsVM -esxiHost "192.168.1.199" -vmName "AD-A.JLAB1.LOCAL" -numCPU 1 -memoryGB 3 -diskGB 50 -networkName "Private-SideA" -windowsISOPath "[datastore1] /ISOs/Windows_Server_2016_Datacenter_EVAL_en-us_14393_refresh.ISO" -vmwareToolsISOPath "[datastore1] /ISOs/Windows_Server_2016_Datacenter_EVAL_en-us_14393_refresh.ISO" -floppyPath "[datastore1] /floppies/windowsFloppy.flp"
function Install-WindowsVM ($esxiHost, $vmName, $numCPU, $memoryGB, $diskGB, $networkName, $windowsISOPath, $vmwareToolsISOPath, $floppyPath) {
    New-VM -Name $vmName -vmhost $esxiHost -NumCpu $numCPU -MemoryGB $memoryGB -DiskGB $diskGB -DiskStorageFormat Thin -GuestID windows7_64Guest -NetworkName $networkName; # guestID set to Win7 for firmware as BIOS not EFI
    Get-VM $vmName | Set-VM -GuestId "windows9Server64Guest" -Confirm:$false;

    New-CDDrive -VM $vmName -IsoPath $windowsISOPath -StartConnected > $null;
    New-CDDrive -VM $vmName -IsoPath $vmwareToolsISOPath -StartConnected > $null;
    New-FloppyDrive -VM $vmName -FloppyImagePath $floppyPath > $null; # note: don't start connected

    Start-VM $vmName;
    Get-FloppyDrive -VM $vmName | Set-FloppyDrive -Connected:$true -Confirm:$false > $null;

    # wait until complete
    while ((Get-VM -Name $vmName).ExtensionData.Guest.ToolsStatus -ne "toolsOk") { Write-Host "Waiting for vmWare tools on $vmName..."; Sleep 60; } Sleep 30;
}

# Set-WindowsVMNetwork -vmName "AD-B.JLAB1.LOCAL" -adminPassword "P@ssword123!" -computerName "AD-B" -ipAddress "10.180.2.200" -gatewayIP "10.180.2.1" -dnsIP "10.180.1.200";
function Set-WindowsVMNetwork ($vmName, $adminPassword, $computerName, $ipAddress, $gatewayIP, $dnsIP, [boolean]$waitToComplete) {
    Write-Host "Set-WindowsVMNetwork called..."
    Invoke-VMScript -VM $vmName -GuestUser "administrator" -GuestPassword $adminPassword -ScriptType PowerShell -ScriptText "
        New-NetIPAddress –InterfaceAlias 'Ethernet0' –IPAddress $ipAddress –PrefixLength 24 -DefaultGateway $gatewayIP; # set IP and gateway (to vyos)
        Disable-NetAdapterBinding –InterfaceAlias 'Ethernet0' –ComponentID ms_tcpip6; # disable ipv6
        Set-DnsClientServerAddress -InterfaceAlias 'Ethernet0' -ServerAddresses ('$dnsIP'); # set DNS
        Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False; # turn off firewall
        REG ADD HKLM\System\CurrentControlSet\Control\Network\NewNetworkWindowOff /F  # Turn off Do you want to allow your PC to be discoverable by other PCs...
        Rename-Computer -NewName '$computerName'; # rename computer
        shutdown /r -t 10; # restart in 10 seconds
        ";

    # wait until complete
    while ((Get-VM -Name $vmName).ExtensionData.Guest.HostName -ne $computerName) { Sleep-Countdown 60 "Waiting for computer name on $vmName..."; } Sleep-Countdown 120 "Computer name set for $vmName, waiting another 2 minutes..."; # goes from "ADMIN..." to "AD-B"

}

function Create-WindowsDomain ($vmName, $adminPassword, $domain, $domainPassword, [boolean]$isNewForest) {
    Write-Host "Create-WindowsDomain called...";
    $script = "Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools;";
    if ($isNewForest) { # create new forest, reboot
        $script += " Install-ADDSForest -DomainName '$domain' -InstallDNS -Force -SafeModeAdministratorPassword ('$domainPassword' | ConvertTo-SecureString -asPlainText -Force);"
    } else { # join existing forest, reboot
        $script += " Install-ADDSDomainController -DomainName '$domain' -InstallDNS -Force -Credential (New-Object System.Management.Automation.PSCredential('$domain\Administrator', ('$domainPassword' | ConvertTo-SecureString -asPlainText -Force))) -SafeModeAdministratorPassword ('$domainPassword' | ConvertTo-SecureString -asPlainText -Force);"
    }
    # Due to domain change, an error will occur ("a general system error occurred: vix error codes"), suppress via -ErrorAction SilentlyContinue (try/catch does not catch it), note: remote powershell errors are just text output (not errors here)
    Invoke-VMScript -VM $vmName -GuestUser "administrator" -GuestPassword $adminPassword -ScriptType PowerShell -ErrorAction SilentlyContinue -ScriptText $script;

    # wait until complete
    while ((Get-VM -Name $vmName).ExtensionData.Guest.HostName -ne "$vmName.$domain") { Sleep-Countdown 60 "Waiting for domain name on $vmName..."; } Sleep-Countdown 600 "Domain name set for $vmName, waiting another 10 minutes..."; # goes from "AD-B" to "AD-B.JLAB1.LOCAL", sleep another 600 seconds since it takes some time
}

function Join-WindowsDomain ($vmName, $adminPassword, $domain, $domainPassword) {
    Write-Host "Join-WindowsDomain called...";
    Invoke-VMScript -VM $vmName -GuestUser "administrator" -GuestPassword $adminPassword -ScriptType PowerShell -ErrorAction SilentlyContinue -ScriptText "
        Add-Computer -DomainName '$domain' -Credential (New-Object System.Management.Automation.PSCredential('$domain\Administrator', ('$domainPassword' | ConvertTo-SecureString -asPlainText -Force)));
        REG ADD 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' /v 'DefaultDomainName' /t REG_SZ /d '$domain' /f # autologin with domain
        shutdown /r -t 10; # restart in 10 seconds
        ";
    # wait until complete
    while ((Get-VM -Name $vmName).ExtensionData.Guest.HostName -ne "$vmName.$domain") { Sleep-Countdown 60 "Waiting for domain name on $vmName..."; } Sleep-Countdown 120 "Domain name set for $vmName, waiting another 120 seconds...";  # goes from "AD-B" to "AD-B.JLAB1.LOCAL"
}

# Finish-WindowsAD -vmName "AD-B" -adminPassword "P@ssword123!" -reverseZone "10.180.2.0/24";
function Finish-WindowsAD ($vmName, $adminPassword, $reverseZone) {
    Write-Host "Finish-WindowsAD called...";

    Invoke-VMScript -VM $vmName -GuestUser "administrator" -GuestPassword $adminPassword -ScriptType PowerShell -ScriptText "
        Add-DnsServerPrimaryZone -NetworkId '$reverseZone' -ReplicationScope 'Forest'; # Adding DNS reverse lookup zone like '10.180.1.0/24'
        w32tm /config /manualpeerlist:pool.ntp.org,0x8 /syncfromflags:MANUAL # set NTP server
        Set-ADUser -Identity 'Administrator' -PasswordNeverExpires:`$true; # stop annoying password expiring warning
        Install-WindowsFeature -name SMTP-Server;
        Set-Service -Name SMTPSVC -StartupType Automatic;
        shutdown /r -t 10; # restart in 10 seconds
    ";
    Sleep-Countdown 120 "Sleeping 120 seconds for reboot..."; # wait for reboot
}

function Finish-WindowsCVP ($vmName, $adminPassword, $cvpISOPath, $cvpPassword) {
    Write-Host "Finish-WindowsCVP called...";
    #install IIS
    Invoke-VMScript -VM $vmName -GuestUser "administrator" -GuestPassword $adminPassword -ScriptType PowerShell -ScriptText "Install-WindowsFeature -Name Web-Server -IncludeManagementTools;";

    # cvp install doesn't seem to have any silent installer, so sendkeys is used
    (Get-VM $vmName | Get-CDDrive)[0] | Set-CDDrive -Connected:$true -IsoPath $cvpISOPath -Confirm:$false; # attach cvp ISO to d:\
    Send-VMKeystrokesText -vmName $vmName -txt "<5><#r><1>D:\CVP\Installer_Windows\setup.exe labonly<enter><45>" -description "run cvp setup.exe labonly";
    Send-VMKeystrokesText -vmName $vmName -txt "<UP><%n><5>" -description "accept license (up arrow), alt-N (next)";
    Send-VMKeystrokesText -vmName $vmName -txt " <1><DOWN> <1><DOWN> <1><%n><5>" -description "space, down, space, down, space, alt-N (next)";
    Send-VMKeystrokesText -vmName $vmName -txt "<%n><5><%n><5><%n><5><%i><150>" -description "next 3 times, then install, sleep 2.5 minutes";
    Send-VMKeystrokesText -vmName $vmName -txt "$cvpPassword<TAB><1>$cvpPassword<1><%n><240>" -description "CVP password, next, sleep 4 minutes for .NET";
    Send-VMKeystrokesText -vmName $vmName -txt "<TAB> " -description "tab space (no hotkey) to finish, CVP will restart";

    Sleep-Countdown 120 "Sleeping 120 seconds for CVP reboot..."; # wait for reboot
}

# Finish-WindowsCCE -vmName "AW-A" -adminPassword "P@ssword123!" -type "CCE_AW" -side "A" -sqlISOPath "[datastore1] /ISOs/SQLServer2017-x64-ENU-Dev.iso" -cceISOPath "[datastore1] /ISOs/CCEInst1251.iso" -sqlPassword "P@ssword123!" -domain "JLAB1.LOCAL"
function Finish-WindowsCCE ($vmName, $adminPassword, $type, $side, $sqlISOPath, $cceISOPath, $sqlPassword, $domain) {
    Write-Host "Finish-WindowsCCE called...";

    # rogger and AW need SQL
    if ($type -in ("CCE_ROGGER", "CCE_AW")) {
        # the PCCE wizard has some strange requirements for SQL, where SQL's data must be on 160GB D: drive and secondary AW must have a 500GB D: drive (but SQL does not need to be on it)
        # to simplify, a D drive will be created for all SQL instances, but will be bigger for AW side B
        if ($type -eq "CCE_AW" -and $side -eq "B") { $dDriveGB = 500; } else { $dDriveGB = 160; }
        Write-Host "Creating D: drive with $dDriveGB GBs";
        New-HardDisk -VM $vmName -CapacityGB $dDriveGB -ThinProvisioned:$true > $null;
        Invoke-VMScript -VM $vmName -GuestUser "administrator" -GuestPassword $adminPassword -ScriptType PowerShell -ScriptText "
            mountvol D: /d # remove drive letter from d: (cd drive)
            (Get-Disk)[1] | Initialize-Disk # initialize the second disk (new one)
            New-Partition -DiskNumber 1 -UseMaximumSize -DriveLetter D | Format-Volume # format it and assign drive letter D
        ";

        # now install SQL
        Write-Host "Installing SQL server...";
        (Get-VM $vmName | Get-CDDrive)[1] | Set-CDDrive -Connected:$true -IsoPath $sqlISOPath -Confirm:$false; Sleep 5; # attach sql ISO to e:\ (second cd drive, where vmware tools was)

        # install SQL silently, the data drive is D:, and then re-order named pipes as required for CCE (via registry)
        Invoke-VMScript -VM $vmName -GuestUser "administrator" -GuestPassword $adminPassword -ScriptType PowerShell -ScriptText "
            e:\setup.exe /SAPWD='$sqlPassword' /IACCEPTSQLSERVERLICENSETERMS=True /IACCEPTPYTHONLICENSETERMS=False /ACTION=Install /SUPPRESSPRIVACYSTATEMENTNOTICE=False /IACCEPTROPENLICENSETERMS=False /ENU=True /QUIET=True /QUIETSIMPLE=False /UpdateEnabled=False /USEMICROSOFTUPDATE=False /FEATURES=SQLENGINE /HELP=False /INDICATEPROGRESS=False /X86=False /INSTANCENAME='MSSQLSERVER' /INSTALLSHAREDDIR='C:\Program Files\Microsoft SQL Server' /INSTALLSHAREDWOWDIR='C:\Program Files (x86)\Microsoft SQL Server' /INSTANCEID='MSSQLSERVER' /SQLTELSVCACCT='NT Service\SQLTELEMETRY' /SQLTELSVCSTARTUPTYPE=Automatic /INSTANCEDIR='C:\Program Files\Microsoft SQL Server' /AGTSVCACCOUNT='NT Service\SQLSERVERAGENT' /AGTSVCSTARTUPTYPE=Automatic /COMMFABRICPORT=0 /COMMFABRICNETWORKLEVEL=0 /COMMFABRICENCRYPTION=0 /MATRIXCMBRICKCOMMPORT=0 /SQLSVCSTARTUPTYPE=Automatic /FILESTREAMLEVEL=0 /ENABLERANU=False /SQLCOLLATION='Latin1_General_BIN' /SQLSVCACCOUNT='NT Service\MSSQLSERVER' /SQLSVCINSTANTFILEINIT=False /SQLSYSADMINACCOUNTS='$domain\Administrator' /SECURITYMODE='SQL' /SQLTEMPDBFILECOUNT=1 /SQLTEMPDBFILESIZE=8 /SQLTEMPDBFILEGROWTH=64 /SQLTEMPDBLOGFILESIZE=8 /SQLTEMPDBLOGFILEGROWTH=64 /ADDCURRENTUSERASSQLADMIN=False /TCPENABLED=1 /NPENABLED=1 /BROWSERSVCSTARTUPTYPE=Automatic /INSTALLSQLDATADIR='D:\'
            REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\MSSQLServer\Client\SNI11.0 /v ProtocolOrder /t REG_MULTI_SZ /d 'sm\0np\0tcp' /f
            REG ADD HKEY_LOCAL_MACHINE\SOFTWARE\WOW6432Node\Microsoft\MSSQLServer\Client\SNI11.0 /v ProtocolOrder /t REG_MULTI_SZ /d 'sm\0np\0tcp' /f
            Set-Service -Name Browser -StartupType Automatic # turn on computer browser service (only needed when running icmdba)
        ";
    }

    Write-Host "Installing CCE...";
    (Get-VM $vmName | Get-CDDrive)[1] | Set-CDDrive -Connected:$true -IsoPath $cceISOPath -Confirm:$false; Sleep 5; # attach cce ISO to e:\ (second cd drive, where vmware tools was)
    Send-VMKeystrokesText -vmName $vmName -txt "<5><#r><1>e:\icm-cce-installer\setup.exe /s<enter>" -description "run cce setup.exe silently";
    while ((VM-SecondsSinceLastReboot -vmName $vmName) -gt 120) { Sleep-Countdown 60 "Waiting for CCE to finish installing..."; } # wait until the server is rebooted
    Write-Host "Finish-WindowsCCE completed";
}

function Install-CiscoVM ($esxiHost, $vmName, $productType, $numCPU, $memoryGB, $diskGB, $networkName, $ciscoISOPath, $adVMName, $adAdminPassword, $computerName, $domain, $ipAddress, $gatewayIP, $dnsIP, $adminPassword, $ntpIP, $securityPassword, $smtpIP, $appUserPassword, $isFirstNode, $firstNodeHostName, $firstNodeIPAddress, $firstNodeVMName) {
    if ($productType -ne 'FINESSE' -and $productType -ne 'VVB' -and $productType -notlike 'CUIC*' -and $productType -notlike 'CM*') { Write-Error "ProductType $productType is not valid"; return; }

    # add host record and reverse pointer
    Invoke-VMScript -VM $adVMName -GuestUser "administrator" -GuestPassword $adAdminPassword -ScriptType PowerShell -ScriptText "Add-DnsServerResourceRecordA -Name '$computerName' -ZoneName '$domain' -IPv4Address $ipAddress -CreatePtr;";

    # add secondary
    if ($isFirstNode -eq $false -and $productType -ne "VVB") {
        Add-SecondaryNodeToFirstNode -productType $productType -firstNodeIPAddress $firstNodeIPAddress -firstNodePassword $adminPassword -secondaryNodeHostName $computerName -secondaryNodeIPAddress $ipAddress -firstNodeVMName $firstNodeVMName; }

    New-VM -Name $vmName -vmhost $esxiHost -NumCpu $numCPU -MemoryGB $memoryGB -DiskGB $diskGB -DiskStorageFormat Thin -GuestID centos7_64Guest -NetworkName $networkName;
    New-CDDrive -VM $vmName -IsoPath $ciscoISOPath -StartConnected;
    Start-VM $vmName;

    Send-VMKeystrokesText -vmName $vmName -txt "<45><tab><1><enter><10>" -description "45 sec boot, skip media";
    if ($productType -like "CUIC*") { Send-VMKeystrokesText -vmName $vmName -txt "<tab><2><tab><2><tab><2> <2>" -description "CUIC: select 4th option (CUIC with Live Data and Ids)"; }
    Send-VMKeystrokesText -vmName $vmName -txt "<tab><1><enter><5><enter><3><enter><3><enter><3><enter><3>" -description "select product, proceed with install, proceed with wizard, no patch, basic install";
    Send-VMKeystrokesText -vmName $vmName -txt "<tab><1><enter><3><enter><3><enter><3>" -description "time zone (default/Los_Angeles), auto NIC, MTU size";
    if ($productType -like "CM*" -or $productType -like "CUIC*") { Send-VMKeystrokesText -vmName $vmName -txt "<enter><3>" -description "no DHCP"; } # no screen for VVB and Finesse (requires static IP)
    Send-VMKeystrokesText -vmName $vmName -txt "$computerName<tab><1>$ipAddress<tab><1>255.255.255.0<tab><1>$gatewayIP<tab><1><enter><3>" -description "name, IP, mask, gateway";
    if ($productType -ne "FINESSE") { Send-VMKeystrokesText -vmName $vmName -txt "<enter><3>" -description "yes DNS"; } # no screen for Finesse (requires DNS)
    Send-VMKeystrokesText -vmName $vmName -txt "$dnsIP<tab><1><tab>$domain<tab><1><enter><3>" -description "dns ip, domain";
    Send-VMKeystrokesText -vmName $vmName -txt "administrator<tab><1>$adminPassword<tab><1>$adminPassword<tab><1><enter><3>" -description "admin login";
    Send-VMKeystrokesText -vmName $vmName -txt "Org<tab><1>Unit<tab><1>Location<tab><1>State<tab><1><tab><1><enter><3>" -description "cert";
    if ($isFirstNode -eq $true -or $productType -eq "VVB") { # VVB is never clustered
        if ($productType -ne "VVB") { Send-VMKeystrokesText -vmName $vmName -txt "<enter><3>" -description "first node yes"; }
        Send-VMKeystrokesText -vmName $vmName -txt "$ntpIP<tab><1><tab><1><tab><1><tab><1><tab><1><enter><3>" -description "ntp";
        Send-VMKeystrokesText -vmName $vmName -txt "$securityPassword<tab><1>$securityPassword<tab><1><enter><3>" -description "security password";
    }
    else { # not first node or not VVB
        Send-VMKeystrokesText -vmName $vmName -txt "<tab><1><enter><3><enter><3><enter><3>" -description "first node no, yes to first node warning, no to network connectivity";
        Send-VMKeystrokesText -vmName $vmName -txt "$firstNodeHostName<tab><1>$firstNodeIPAddress<tab><1>$securityPassword<tab><1>$securityPassword<tab><1><enter><3>" -description "first node host name, IP, security password x 2";
    }

    if ($productType -ne "FINESSE") { Send-VMKeystrokesText -vmName $vmName -txt "<enter><3>$smtpIP<tab><1><enter><3>" -description "smtp yes, then enter smtp IP"; } # Finesse has no SMTP screen
    if ($productType -like "CM*" -and $isFirstNode) { Send-VMKeystrokesText -vmName $vmName -txt "<tab><1><tab><1><tab><1> <2><tab><1><enter><3>" -description "smart call home"; } # only CUCM publisher has smart call home screen
    if ($isFirstNode -or $productType -eq "VVB") { Send-VMKeystrokesText -vmName $vmName -txt "administrator<tab><1>$appUserPassword<tab><1>$appUserPassword<tab><1><enter><3>" -description "app user login"; } # only primary or VVB
    Send-VMKeystrokesText -vmName $vmName -txt "<enter><3>" -description "install";

    # wait until complete
    while ((Test-NetConnection -ComputerName $ipAddress -Port 443).TcpTestSucceeded -eq $false) { Write-Host "Waiting for web page on $vmName..."; Sleep 300; } Write-Host "Web page available for $vmName";
}

# Invoke-API -url "https://10.171.1.205/oampapi/rest/servers" -adminUsername "administrator" -adminPassword "P@ssword123!" -contentType "application/json" -method "POST" -body "{"type":"MEMBER","name":"mytest2","host":"10.171.2.242"}"
function Invoke-API ($url, $adminUsername, $adminPassword, $body, $contentType, $method) {
    # trust all certs (e.g. self-signed certs)
    add-type "using System.Net; using System.Security.Cryptography.X509Certificates; public class TrustAllCertsPolicy : ICertificatePolicy { public bool CheckValidationResult( ServicePoint srvPoint, X509Certificate certificate, WebRequest request, int certificateProblem) { return true; } }";
    [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy;
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12;

    $basicAuth = [System.Convert]::ToBase64String([System.Text.Encoding]::ASCII.GetBytes("$($adminUsername):$($adminPassword)"))
    try {
        $ret = Invoke-WebRequest -Uri $url -Method $method -Headers @{"Accept"=$contentType; "Authorization"="Basic $basicAuth"} -ContentType $contentType -Body $body;
    } catch { }
    return $ret.StatusCode;
}

function Add-SecondaryNodeToFirstNode ($productType, $firstNodeIPAddress, $firstNodePassword, $secondaryNodeHostName, $secondaryNodeIPAddress, $firstNodeVMName) {

    switch ($productType) {
        "FINESSE" {
            Write-Host "Adding Finesse side B to $firstNodeIPAddress";
            Invoke-API -url "https://$firstNodeIPAddress/finesse/api/ClusterConfig" -adminUsername "administrator" -adminPassword "$firstNodePassword" -contentType "application/xml" -method "PUT" -body "<ClusterConfig><secondaryNode><host>$secondaryNodeHostName</host></secondaryNode></ClusterConfig>";
        }
        "CUIC_SUBSCRIBER"    {
            Write-Host "Adding CUIC subscriber to $firstNodeIPAddress";
            Invoke-API -url "https://$firstNodeIPAddress/oampapi/rest/servers" -adminUsername "administrator" -adminPassword "$firstNodePassword" -contentType "application/json" -method "POST" -body "{`"type`":`"MEMBER`",`"name`":`"$secondaryNodeHostName`",`"host`":`"$secondaryNodeIPAddress`"}";
        }
        "CM_SUBSCRIBER"    {
            Write-Host "Adding CUCM subscriber to $firstNodeVMName";
            Send-VMKeystrokesText -vmName $firstNodeVMName -txt "administrator<enter><1>$firstNodePassword<enter><15>set network cluster subscriber details CUCM $secondaryNodeHostName<enter><15>exit<enter><1>" -description "adding subscriber to cucm";
        }
    }
}

function Install-VyOSVM ($esxiHost, $vmName, $numCPU=1, $memoryGB=0.5, $diskGB=2, $iso, $networkNames, $ipPrefixSideA, $ipPrefixSideB, $newPassword="vyos") {

    New-VM -Name $vmName -vmhost $esxiHost -NumCpu $numCPU -MemoryGB $memoryGB -DiskGB $diskGB -DiskStorageFormat Thin -GuestID otherGuest64 -NetworkName $networkNames;
    Get-VM $vmName | Set-VM -GuestId "other5xLinux64Guest" -Confirm:$false; # change to correct guest after VM creation (New-VM sets as EFI boot otherwise)
    New-CDDrive -VM $vmName -IsoPath $iso -StartConnected;

    Start-VM $vmName;
    Send-VMKeystrokesText -vmName $vmName -txt "<45>vyos<enter><1>vyos<enter><5>install image<enter><5><enter><5><enter><5><enter><5>Yes<enter><5><enter><5><enter><5><enter><5>$newPassword<enter><1>$newPassword<enter><2><enter><2>reboot now<enter><2>" -description "waiting 45 for login screen, installing image";
    Send-VMKeystrokesText -vmName $vmName -txt "<45>vyos<enter><1>$newPassword<enter><5>configure<enter><5>" -description "waiting for reboot, login, config mode";
    Send-VMKeystrokesText -vmName $vmName -txt "set service ssh port 22<enter><1>set system ipv6 disable<enter><1>" -description "turn on ssh, disable ipv6";
    Send-VMKeystrokesText -vmName $vmName -txt "set nat source rule 10 outbound-interface eth0<enter><1>set nat source rule 10 translation address masquerade<enter><1>set service dns forwarding dhcp eth0<enter><1>" -description "allow dhcp forwarding";
    Send-VMKeystrokesText -vmName $vmName -txt "set interfaces ethernet eth0 address dhcp<enter><1>" -description "public NIC as DHCP";
    Send-VMKeystrokesText -vmName $vmName -txt "set interfaces ethernet eth1 address $ipPrefixSideA.1/24<enter><1>" -description "side A NIC as static";
    Send-VMKeystrokesText -vmName $vmName -txt "set service dns forwarding allow-from $ipPrefixSideA.0/24<enter><1>set service dns forwarding listen-address $ipPrefixSideA.1<enter><1>" -description "side A NIC forward DNS";
    Send-VMKeystrokesText -vmName $vmName -txt "set interfaces ethernet eth2 address $ipPrefixSideB.1/24<enter><1>" -description "side B NIC as static";
    Send-VMKeystrokesText -vmName $vmName -txt "set service dns forwarding allow-from $ipPrefixSideB.0/24<enter><1>set service dns forwarding listen-address $ipPrefixSideB.1<enter><1>" -description "side B NIC forward DNS";
    Send-VMKeystrokesText -vmName $vmName -txt "commit<enter><2>save<enter><2>exit<enter><2>reboot now<enter><2>" -description "save and reboot";
}

function Run-DomainManager ($vmName, $adminPassword, $facilityName, $instanceName) {
    Write-Host "Running domain manager on $vmName, setting facility to $facilityName and instance to $instanceName";
    Send-VMKeystrokesText -vmName $vmName -txt "<#r><1>C:\icm\bin\DomainManager.exe<enter><5>" -description "start domain manager";
    Send-VMKeystrokesText -vmName $vmName -txt "<RIGHT><2><%a><2><ENTER><5><%a><2>$facilityName<2><ENTER><5><%a><2>$instanceName<2><ENTER><5><%c><2>" -description "add domain root, facility, and instance, close it";

    Write-Host "Creating AD 'ServiceAccount', and add it to all AD security groups..."
    Invoke-VMScript -VM $vmName -GuestUser "administrator" -GuestPassword $adminPassword -ScriptType PowerShell -ScriptText "
        New-ADUser -Name 'ServiceAccount' -ChangePasswordAtLogon:`$false -PasswordNeverExpires:`$true -Enabled:`$true -AccountPassword (ConvertTo-SecureString -AsPlainText '$adminPassword' -Force);
        `$groups = @('Domain Admins', 'Cisco_ICM_Config', 'Cisco_ICM_Setup', '$($facilityName)_Config', '$($facilityName)_Setup', '$($facilityName)_$($instanceName)_Config', '$($facilityName)_$($instanceName)_Setup', '$($facilityName)_$($instanceName)_Service');
        foreach (`$group in `$groups) {
            Add-ADGroupMember -Identity `$group -Members 'ServiceAccount'; Write-Host `"Added to group `$group`"; }
    ";
}

# exports and imports self-signed certs from various components to CCE and CVP
# relies on script A:\functions.ps1
function Import-Certs ($vmName, $adminPassword, $vms, $domain) {
    Write-Host "Exporting and importing certs on $vmName";

    $imports = ". A:\functions.ps1`n";
    $exports = ". A:\functions.ps1`n";
    #$i = 0;
    foreach ($vm in $vms) {
        $url = "$($vm.name).$($domain)"; # e.g. CVP-A.JLAB1.LOCAL
        $ports = switch -Wildcard ($vm.type) { "*CVP*" { @('9443', '8111') } "*CM*" { @('443', '8443') } "*FINESSE*" { @('443') } "*VVB*" { @('443') } "*CCE*" { @('443', '7890') } "*CUIC*" { @('443', '8553') } }
        foreach ($port in $ports) {
            $site = "$($url):$port";
            $alias = $site.Replace(":", "_");
            $fileName = "$alias.cer"; # e.g. CVP-A.JLAB1.LOCAL.cer
            $imports += "Export-CertFile '$($url):$($port)' 'c:\temp\$fileName';`n"
            $exports += "Import-CertFile $alias' 'c:\temp\$fileName';`n"
        }
    }
    # note: scripttext seems to have a max length, so split into two commands
    Invoke-VMScript -VM $vmName -GuestUser "administrator" -GuestPassword $adminPassword -ScriptType PowerShell -ScriptText $imports;
    Invoke-VMScript -VM $vmName -GuestUser "administrator" -GuestPassword $adminPassword -ScriptType PowerShell -ScriptText $exports;
}

function Create-InventoryCSV ($esxiHost, $vms, $password, $domain, $outputFile) {
    Write-Host "Creating $outputFile";
    $out = "operation,name,machineType,publicAddress,publicAddressServices,privateAddress,side`r`n";
    $out += "CREATE,sideA,VM_HOST,$esxiHost,,,sideA`r`nCREATE,sideB,VM_HOST,$esxiHost,,,sideB`r`n";
    foreach ($vm in $vms.Where({$PSItem.type -like "CCE*" -or $PSItem.type -like "CM*" -or $PSItem.type -like "CVP" -or $PSItem.type -like "FINESSE" -or $PSItem.type -like "CUIC*"})) {
        $out += "CREATE,$($vm.name),$($vm.type),$($vm.ip),";
        if ($vm.type -eq "CVP") { $out += "type=CVP_WSM&userName=administrator@$domain&password=$password"; }
        elseif ($vm.type -eq "CM_PUBLISHER") { $out += "type=AXL&userName=administrator&password=$password"; }
        elseif ($vm.type -eq "CCE_AW" -and $vm.side -eq "A") { $out += "type=DIAGNOSTIC_PORTAL&userName=administrator@$domain&password=$password"; }
        elseif ($vm.type -eq "CUIC_PUBLISHER") { $out += "type=DIAGNOSTIC_PORTAL&userName=administrator&password=$password; type=IDS&userName=administrator&password=$password"; }
        elseif ($vm.type -eq "FINESSE" -and $vm.side -eq "A") { $out += "type=DIAGNOSTIC_PORTAL&userName=administrator&password=$password"; }
        $out += ",";
        if ($vm.type -like "*ROGGER" -or $vm.type -like "*PG") { $out += $vm.ip; }
        $out += ",side$($vm.side)`r`n";
    }
    $out | Out-File -FilePath $outputFile -Encoding ascii;
}