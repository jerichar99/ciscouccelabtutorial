#Connect-VIServer -Server 192.168.1.199 -User root -Password P@ssword123!;

Invoke-VMScript -VM "AD-A.JLAB1.LOCAL" -GuestUser "administrator" -GuestPassword "P@ssword123!" -ScriptType PowerShell -ScriptText "
Add-DnsServerResourceRecordA -Name cucm-pub-a -ZoneName JLAB1.LOCAL -IPv4Address 10.180.1.211 -CreatePtr;
";

New-VM -Name "CUCM-PUB-A.JLAB1.LOCAL" -vmhost "192.168.1.199" -NumCpu 1 -MemoryGB 4 -DiskGB 80 -DiskStorageFormat Thin -GuestID centos7_64Guest -NetworkName "Private-SideA";
New-CDDrive -VM "CUCM-PUB-A.JLAB1.LOCAL" -IsoPath "[datastore1] /ISOs/cucm_UCSInstall_UCOS_12.5.1.12900-115.sgn_bootable.iso" -StartConnected;
Start-VM "CUCM-PUB-A.JLAB1.LOCAL";

cd (Split-Path $MyInvocation.MyCommand.Path) # change directory to this script location
. .\_installFunctions.ps1

Send-VMKeystrokesText -vmName "CUCM-PUB-A.JLAB1.LOCAL" -txt "<45><tab><enter><10><tab><enter><5><enter><3>" -description "45 sec boot, skip media, select product, proceed with install";
Send-VMKeystrokesText -vmName "CUCM-PUB-A.JLAB1.LOCAL" -txt "<enter><2><enter><2><enter><2><tab><enter><2><enter><2><enter><2><enter><2>" -description "proceed, no patch, basic install, time zone (default), auto NIC, MTU size, DHCP (no)";
Send-VMKeystrokesText -vmName "CUCM-PUB-A.JLAB1.LOCAL" -txt "cucm-pub-a<tab>10.180.1.211<tab>255.255.255.0<tab>10.180.1.1<tab><enter><2>" -description "name, IP, mask, gateway";
Send-VMKeystrokesText -vmName "CUCM-PUB-A.JLAB1.LOCAL" -txt "<enter><2>10.180.1.200<tab><tab>jlab1.local<tab><enter><2>" -description "dns (yes), dns ip, domain";
Send-VMKeystrokesText -vmName "CUCM-PUB-A.JLAB1.LOCAL" -txt "administrator<tab>P@ssword123!<tab>P@ssword123!<tab><enter><2>" -description "admin login";
Send-VMKeystrokesText -vmName "CUCM-PUB-A.JLAB1.LOCAL" -txt "n<tab>n<tab>n<tab>n<tab><tab><enter><2>" -description "cert";
Send-VMKeystrokesText -vmName "CUCM-PUB-A.JLAB1.LOCAL" -txt "<enter><2>10.180.1.200<tab><tab><tab><tab><tab><enter><2>" -description "first node, ntp";
Send-VMKeystrokesText -vmName "CUCM-PUB-A.JLAB1.LOCAL" -txt "P@ssword123!<tab>P@ssword123!<tab><enter><2>" -description "security password";
Send-VMKeystrokesText -vmName "CUCM-PUB-A.JLAB1.LOCAL" -txt "<enter><2>10.180.1.200<tab><enter><2>" -description "smtp";
Send-VMKeystrokesText -vmName "CUCM-PUB-A.JLAB1.LOCAL" -txt "<tab><tab><tab> <tab><enter><2>" -description "smart call home";
Send-VMKeystrokesText -vmName "CUCM-PUB-A.JLAB1.LOCAL" -txt "administrator<tab>P@ssword123!<tab>P@ssword123!<tab><enter><2>" -description "app user login";
Send-VMKeystrokesText -vmName "CUCM-PUB-A.JLAB1.LOCAL" -txt "<enter><2>" -description "install";
