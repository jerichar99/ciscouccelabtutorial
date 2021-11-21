$ErrorActionPreference = "Stop"
cd (Split-Path $MyInvocation.MyCommand.Path) # change directory to this script location
. .\_installFunctions.ps1

#Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false > $null;
#Connect-VIServer -Server 192.168.1.199 -User root -Password P@ssword123! > $null;

New-VM -Name "ROUTER.JLAB1.LOCAL" -vmhost "192.168.1.199" -NumCpu 1 -MemoryGB 0.5 -DiskGB 2 -DiskStorageFormat Thin -GuestID otherGuest64 -NetworkName @("Public Network","Private-SideA","Private-SideB");
Get-VM "ROUTER.JLAB1.LOCAL" | Set-VM -GuestId "other5xLinux64Guest" -Confirm:$false; # change to correct guest after VM creation (New-VM sets as EFI boot otherwise)
New-CDDrive -VM "ROUTER.JLAB1.LOCAL" -IsoPath "[datastore1] /ISOs/vyos-1.4-rolling-202108160117-amd64.iso" -StartConnected;

Start-VM "ROUTER.JLAB1.LOCAL";
Send-VMKeystrokesText -vmName "ROUTER.JLAB1.LOCAL" -txt "<45>vyos<enter><1>vyos<enter><5>install image<enter><5><enter><5><enter><5><enter><5>Yes<enter><5><enter><5><enter><5><enter><5>vyos<enter><1>vyos<enter><2><enter><2>reboot now<enter><2>" -description "waiting 45 for login screen, installing image";
Send-VMKeystrokesText -vmName "ROUTER.JLAB1.LOCAL" -txt "<45>vyos<enter><1>vyos<enter><5>configure<enter><5>" -description "waiting for reboot, login, config mode";
Send-VMKeystrokesText -vmName "ROUTER.JLAB1.LOCAL" -txt "set service ssh port 22<enter><1>set system ipv6 disable<enter><1>" -description "turn on ssh, disable ipv6";
Send-VMKeystrokesText -vmName "ROUTER.JLAB1.LOCAL" -txt "set nat source rule 10 outbound-interface eth0<enter><1>set nat source rule 10 translation address masquerade<enter><1>set service dns forwarding dhcp eth0<enter><1>" -description "allow dhcp forwarding";
Send-VMKeystrokesText -vmName "ROUTER.JLAB1.LOCAL" -txt "set interfaces ethernet eth0 address dhcp<enter><1>" -description "public NIC as DHCP";
Send-VMKeystrokesText -vmName "ROUTER.JLAB1.LOCAL" -txt "set interfaces ethernet eth1 address 10.180.1.1/24<enter><1>" -description "side A NIC as static";
Send-VMKeystrokesText -vmName "ROUTER.JLAB1.LOCAL" -txt "set service dns forwarding allow-from 10.180.1.0/24<enter><1>set service dns forwarding listen-address 10.180.1.1<enter><1>" -description "side A NIC forward DNS";
Send-VMKeystrokesText -vmName "ROUTER.JLAB1.LOCAL" -txt "set interfaces ethernet eth2 address 10.180.2.1/24<enter><1>" -description "side B NIC as static";
Send-VMKeystrokesText -vmName "ROUTER.JLAB1.LOCAL" -txt "set service dns forwarding allow-from 10.180.2.0/24<enter><1>set service dns forwarding listen-address 10.180.2.1<enter><1>" -description "side B NIC forward DNS";
Send-VMKeystrokesText -vmName "ROUTER.JLAB1.LOCAL" -txt "commit<enter><2>save<enter><2>exit<enter><2>reboot now<enter><2>" -description "save and reboot";

