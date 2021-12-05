function Sleep-Countdown { param($msg, $seconds) For ($i=$seconds; $i -gt 0; $i--) { Write-Progress -Activity $msg -SecondsRemaining $i; Start-Sleep 1 } }

# vmGV from Get-View, $hidCode "0x4f" right arrow, "0x50" left arrow, "0x28" enter, see https://gist.github.com/MightyPork/6da26e382a7ad91b5496ee55fdc73db2
# Send-VMKeystrokes -vmGV $vmGV -hidCode "0x4f"
function Send-VMKeystroke { param($vmGV, [string]$hidCode, $leftAlt, $leftShift, $leftControl)
    $tmp = New-Object VMware.Vim.UsbScanCodeSpecKeyEvent -Property @{ UsbHidCode = ([Convert]::ToInt64($hidCode, "16") -shl 16) -bor 0007 };
    $tmp.Modifiers = (New-Object Vmware.Vim.UsbScanCodeSpecModifierType -Property @{ LeftAlt = $leftAlt; LeftShift = $leftShift; LeftControl = $leftControl; });
    $spec = New-Object Vmware.Vim.UsbScanCodeSpec -Property @{ KeyEvents = $tmp};
    $vmGV.PutUsbScanCodes($spec) > $null;
    Sleep -Milliseconds 500;
}

function Send-VMKeystrokes { param($vmGV, [string[]] $hidCodes)
    foreach($hidCode in $hidCodes) {
        Send-VMKeystroke -vmGV $vmGV -hidCode $hidCode; }
}

# sends keyboard presses into the VM, using a complicated mapping of characters to USB HID scan codes
# note: not exhaustive mapping, more characters can be added
# Send-VMKeystrokesText -vmName "ROUTER.JLAB1.LOCAL" -txt "myPassword" will type "m y P a s s w o r d" into the VM session
# Special characters: <tab>, <enter>, <X> (sleep X seconds), <left> arrow left, <up>, <down>, <right>, <all> select all, <copy>, <cut>, <paste>, <del>, <win> (windows left key)
function Send-VMKeystrokesText { param($vmName, [string]$txt, [string]$description)
    $vmGV = Get-View -ViewType VirtualMachine -Filter @{"Name" = $vmName };
    if ($description -ne $null) { Write-Host $description; }

    $chars = $txt.ToCharArray();
    # loop through each character in $txt
    for ($i = 0; $i -le $chars.Length ; $i++) {
        $hidCode = 0;
        $shift = $control = $alt = $false;

        # special commands like <tab>, <enter>, <5> (5 second sleep) etc.
        if ($chars[$i] -eq '<') {
            $cmd = "";
            while ($chars[++$i] -ne '>') { # accumulate characters until >
                $cmd = $cmd + $chars[$i];
            }
            if ($cmd -match "^\d+$") { Sleep -Seconds $cmd; continue; } # sleep and go back to for loop top
            $hidCode = switch ($cmd) { "tab" { 43 } "enter" { 40 } "right" { 79 } "left" { 80 } "down" { 81 } "up" { 82 } "all" { $control = $true; 4 } "del" { 76 } "copy" { $control = $true; 6 } "cut" { $control = $true; 27 } "paste" { $control = $true; 25 } "win" { 227 }  }
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
        # convert number to hex (e.g. 4 => 0x04, 31 => 0x1F)
        $hidCodeHex = "0x"+([byte][char]$hidCode).ToString("X2");
        Send-VMKeystroke -vmGV $vmGV -hidCode $hidCodeHex -leftAlt $alt -leftShift $shift -leftControl $control;
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
    while ((Get-VM -Name $vmName).ExtensionData.Guest.HostName -ne $computerName) { Write-Host "Waiting for computer name on $vmName..."; Sleep 60; } Sleep 60; # goes from "ADMIN..." to "AD-B"

}

function Create-WindowsDomain ($vmName, $adminPassword, $domain, $domainPassword, [boolean]$isNewForest) {
    $script = "Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools;";
    if ($isNewForest) { # create new forest, reboot
        $script += " Install-ADDSForest -DomainName '$domain' -InstallDNS -Force -SafeModeAdministratorPassword ('$domainPassword' | ConvertTo-SecureString -asPlainText -Force);"
    } else { # join existing forest, reboot
        $script += " Install-ADDSDomainController -DomainName '$domain' -InstallDNS -Force -Credential (New-Object System.Management.Automation.PSCredential('$domain\Administrator', ('$domainPassword' | ConvertTo-SecureString -asPlainText -Force))) -SafeModeAdministratorPassword ('$domainPassword' | ConvertTo-SecureString -asPlainText -Force);"
    }
    # Due to domain change, an error will occur ("a general system error occurred: vix error codes"), suppress via -ErrorAction SilentlyContinue (try/catch does not catch it), note: remote powershell errors are just text output (not errors here)
    Invoke-VMScript -VM $vmName -GuestUser "administrator" -GuestPassword $adminPassword -ScriptType PowerShell -ErrorAction SilentlyContinue -ScriptText $script;

    # wait until complete
    while ((Get-VM -Name $vmName).ExtensionData.Guest.HostName -ne $vmName) { Write-Host "Waiting for domain name on $vmName..."; Sleep 60; } Sleep 180; # goes from "AD-B" to "AD-B.JLAB1.LOCAL", sleep another 180 seconds since it takes some time
}

function Join-WindowsDomain ($vmName, $adminPassword, $domain, $domainPassword) {
    Invoke-VMScript -VM $vmName -GuestUser "administrator" -GuestPassword $adminPassword -ScriptType PowerShell -ErrorAction SilentlyContinue -ScriptText "
        Add-Computer -DomainName '$domain' -Credential (New-Object System.Management.Automation.PSCredential('$domain\Administrator', ('$domainPassword' | ConvertTo-SecureString -asPlainText -Force)));
        REG ADD 'HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' /v 'DefaultDomainName' /t REG_SZ /d '$domain' /f # autologin with domain
        shutdown /r -t 10; # restart in 10 seconds
        ";
    # wait until complete
    while ((Get-VM -Name $vmName).ExtensionData.Guest.HostName -ne $vmName) { Write-Host "Waiting for domain name on $vmName..."; Sleep 60; } Sleep 30; # goes from "AD-B" to "AD-B.JLAB1.LOCAL"
}

# Finish-WindowsAD -vmName "AD-B.JLAB1.LOCAL" -adminPassword "P@ssword123!" -reverseZone "10.180.2.0/24";
function Finish-WindowsAD ($vmName, $adminPassword, $reverseZone) {
    Invoke-VMScript -VM $vmName -GuestUser "administrator" -GuestPassword $adminPassword -ScriptType PowerShell -ScriptText "
        Add-DnsServerPrimaryZone -NetworkId '$reverseZone' -ReplicationScope 'Forest'; # Adding DNS reverse lookup zone like '10.180.1.0/24'
        Set-ADUser -Identity 'Administrator' -PasswordNeverExpires:`$true; # stop annoying password expiring warning
        Install-WindowsFeature -name SMTP-Server;
        Set-Service -Name SMTPSVC -StartupType Automatic;
        shutdown /r -t 10; # restart in 10 seconds
    ";
    Sleep 90; # wait for reboot
}


function Install-CiscoVM ($esxiHost, $vmName, $productType, $numCPU, $memoryGB, $diskGB, $networkName, $ciscoISOPath, $adVMName, $adAdminPassword, $computerName, $domain, $ipAddress, $gatewayIP, $dnsIP, $adminPassword, $ntpIP, $securityPassword, $smtpIP, $appUserPassword, $isFirstNode, $firstNodeHostName, $firstNodeIPAddress) {
    # add host record and reverse pointer
    #Invoke-VMScript -VM $adVMName -GuestUser "administrator" -GuestPassword $adAdminPassword -ScriptType PowerShell -ScriptText "Add-DnsServerResourceRecordA -Name '$computerName' -ZoneName '$domain' -IPv4Address $ipAddress -CreatePtr;";

    #New-VM -Name $vmName -vmhost $esxiHost -NumCpu $numCPU -MemoryGB $memoryGB -DiskGB $diskGB -DiskStorageFormat Thin -GuestID centos7_64Guest -NetworkName $networkName;
    #New-CDDrive -VM $vmName -IsoPath $ciscoISOPath -StartConnected;
    Start-VM $vmName;

    Send-VMKeystrokesText -vmName $vmName -txt "<45><tab><enter><10>" -description "45 sec boot, skip media";
    if ($productType -eq "CUIC") { Send-VMKeystrokesText -vmName $vmName -txt "<tab><2><tab><2><tab><2> <2>" -description "CUIC: select 4th option (CUIC with Live Data and Ids)"; }
    Send-VMKeystrokesText -vmName $vmName -txt "<tab><2><enter><10><enter><3><enter><3><enter><3><enter><3>" -description "select product, proceed with install, proceed with wizard, no patch, basic install";
    Send-VMKeystrokesText -vmName $vmName -txt "<tab><2><enter><3><enter><3><enter><3>" -description "time zone (default/Los_Angeles), auto NIC, MTU size";
    if ($productType -eq "CUCM" -or $productType -eq "CUIC") { Send-VMKeystrokesText -vmName $vmName -txt "<enter><3>" -description "no DHCP"; } # no screen for VVB and Finesse (requires static IP)
    Send-VMKeystrokesText -vmName $vmName -txt "$computerName<tab><2>$ipAddress<tab><2>255.255.255.0<tab><2>$gatewayIP<tab><2><enter><3>" -description "name, IP, mask, gateway";
    if ($productType -ne "FINESSE") { Send-VMKeystrokesText -vmName $vmName -txt "<enter><3>" -description "yes DNS"; } # no screen for Finesse (requires DNS)
    Send-VMKeystrokesText -vmName $vmName -txt "$dnsIP<tab><2><tab>$domain<tab><2><enter><3>" -description "dns ip, domain";
    Send-VMKeystrokesText -vmName $vmName -txt "administrator<tab><2>$adminPassword<tab><2>$adminPassword<tab><2><enter><3>" -description "admin login";
    Send-VMKeystrokesText -vmName $vmName -txt "Org<tab><2>Unit<tab><2>Location<tab><2>State<tab><2><tab><2><enter><3>" -description "cert";
    if ($isFirstNode -eq $true -or $productType -eq "VVB") { # VVB is never clustered
        if ($productType -ne "VVB") { Send-VMKeystrokesText -vmName $vmName -txt "<enter><3>" -description "first node yes"; }
        Send-VMKeystrokesText -vmName $vmName -txt "$ntpIP<tab><2><tab><2><tab><2><tab><2><tab><2><enter><3>" -description "ntp";
        Send-VMKeystrokesText -vmName $vmName -txt "$securityPassword<tab><2>$securityPassword<tab><2><enter><3>" -description "security password";
    }
    else { # not first node or not VVB
        Send-VMKeystrokesText -vmName $vmName -txt "<tab><2><enter><3><enter><3><enter><3>" -description "first node no, yes to first node warning, no to network connectivity";
        Send-VMKeystrokesText -vmName $vmName -txt "$firstNodeHostName<tab><2>$firstNodeIPAddress<tab><2>$securityPassword<tab><2>$securityPassword<tab><2><enter><3>" -description "first node host name, IP, security password x 2";
    }

    if ($productType -ne "FINESSE") { Send-VMKeystrokesText -vmName $vmName -txt "<enter><3>$smtpIP<tab><2><enter><3>" -description "smtp yes, then enter smtp IP"; } # Finesse has no SMTP screen
    if ($productType -eq "CUCM" -and $isFirstNode) { Send-VMKeystrokesText -vmName $vmName -txt "<tab><2><tab><2><tab><2> <2><tab><2><enter><3>" -description "smart call home"; } # only CUCM publisher has smart call home screen
    if ($isFirstNode -or $productType -eq "VVB") { Send-VMKeystrokesText -vmName $vmName -txt "administrator<tab><2>$appUserPassword<tab><2>$appUserPassword<tab><2><enter><3>" -description "app user login"; } # only primary or VVB
    #Send-VMKeystrokesText -vmName $vmName -txt "<enter><3>" -description "install";
}
