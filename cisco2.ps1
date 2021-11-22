#Connect-VIServer -Server 192.168.1.199 -User root -Password P@ssword123!;

cd (Split-Path $MyInvocation.MyCommand.Path) # change directory to this script location
. .\_installFunctions.ps1

Install-CiscoVM -esxiHost "192.168.1.199" -vmName "CUCM-SUB-A.JLAB1.LOCAL" -numCPU 1 -memoryGB 4 -diskGB 80 -networkName "Private-SideA" -ciscoISOPath "[datastore1] /ISOs/cucm_UCSInstall_UCOS_12.5.1.12900-115.sgn_bootable.iso" `
    -adVMName "AD-A.JLAB1.LOCAL" -adAdminPassword "P@ssword123!" -computerName "cucm-sub-a" -domain "jlab.local" -ipAddress "10.180.1.201" -gatewayIP "10.180.1.1" -dnsIP "10.180.1.200" -adminPassword "P@ssword123!" `
    -ntpIP "10.180.1.200" -securityPassword "P@ssword123!" -smtpIP "10.180.1.200" -appUserPassword "P@ssword123!";