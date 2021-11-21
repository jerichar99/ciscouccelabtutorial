
#Connect-VIServer -Server "192.168.1.199" -User root -Password P@ssword123!;

 cd (Split-Path $MyInvocation.MyCommand.Path) # change directory to this script location
. .\_installFunctions2.ps1

Install-WindowsVM -esxiHost "192.168.1.199" -vmName "AD-B.JLAB1.LOCAL" -waitToComplete:$true -numCPU 1 -memoryGB 3 -diskGB 50 -networkName "Private-SideB" -windowsISOPath "[datastore1] /ISOs/Windows_Server_2016_Datacenter_EVAL_en-us_14393_refresh.ISO" -vmwareToolsISOPath "[datastore1] /ISOs/vmwaretools_windows.iso" -floppyPath "[datastore1] /floppies/windowsFloppy.flp";
Set-WindowsVMNetwork -vmName "AD-B.JLAB1.LOCAL" -waitToComplete:$true -adminPassword "P@ssword123!" -computerName "AD-B" -ipAddress "10.180.2.200" -gatewayIP "10.180.2.1" -dnsIP "10.180.1.200";
Create-WindowsDomain -vmName "AD-B.JLAB1.LOCAL" -adminPassword "P@ssword123!" -domain "JLAB1.LOCAL" -domainPassword "P@ssword123!" -isNewForest:$false;
Finish-WindowsAD -vmName "AD-B.JLAB1.LOCAL" -adminPassword "P@ssword123!" -reverseZone "10.180.2.0/24";
