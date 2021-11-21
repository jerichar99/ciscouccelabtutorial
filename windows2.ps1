#Connect-VIServer -Server 192.168.1.199 -User root -Password P@ssword123!;

Invoke-VMScript -VM "AD-A.JLAB1.LOCAL" -GuestUser "administrator" -GuestPassword "P@ssword123!" -ScriptType PowerShell -ScriptText "
    New-NetIPAddress –InterfaceAlias 'Ethernet0' –IPAddress 10.180.1.200 –PrefixLength 24 -DefaultGateway 10.180.1.1; # set IP and gateway (to vyos)
    Disable-NetAdapterBinding –InterfaceAlias 'Ethernet0' –ComponentID ms_tcpip6; # disable ipv6
    Set-DnsClientServerAddress -InterfaceAlias 'Ethernet0' -ServerAddresses ('127.0.0.1'); # set DNS (to itself as DNS server eventually)
    Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled False; # turn off firewall
    REG ADD HKLM\System\CurrentControlSet\Control\Network\NewNetworkWindowOff /F  # Turn off Do you want to allow your PC to be discoverable by other PCs...
    Rename-Computer -NewName 'AD-A'; # rename computer
    shutdown /r -t 10; # restart in 10 seconds
";

# Due to domain change, an error will occur ("a general system error occurred: vix error codes"), suppress via -ErrorAction SilentlyContinue (try/catch does not catch it), note: remote powershell errors are just text output (not errors here)
Invoke-VMScript -VM "AD-A.JLAB1.LOCAL" -GuestUser "administrator" -GuestPassword "P@ssword123!" -ScriptType PowerShell -ErrorAction SilentlyContinue -ScriptText "
    Install-WindowsFeature -name AD-Domain-Services -IncludeManagementTools; # install domain tools
    Install-ADDSForest -DomainName JLAB1.LOCAL -InstallDNS -Force -SafeModeAdministratorPassword ('P@ssword123!' | ConvertTo-SecureString -asPlainText -Force); # create new forest, DNS, reboot
";

Invoke-VMScript -VM "AD-A.JLAB1.LOCAL" -GuestUser "administrator" -GuestPassword "P@ssword123!" -ScriptType PowerShell -ErrorAction SilentlyContinue -ScriptText "
    Add-DnsServerPrimaryZone -NetworkId '10.180.1.0/24' -ReplicationScope 'Forest'; # Adding DNS reverse lookup zone
    Set-ADUser -Identity 'Administrator' -PasswordNeverExpires:`$true; # stop annoying password expiring warning
    Install-WindowsFeature -name SMTP-Server;
    Set-Service -Name SMTPSVC -StartupType Automatic;
    shutdown /r -t 10; # restart in 10 seconds
";




