Connect-VIServer -Server 192.168.1.199 -User root -Password P@ssword123!;

cd (Split-Path $MyInvocation.MyCommand.Path) # change directory to this script location
. .\_installFunctions2.ps1

$esxiHost = "192.168.1.199"
$password = "P@ssword123!";
$domain = "JLAB1.LOCAL";
$cucmISO = "[datastore1] /ISOs/UCSInstall_FINESSE_12.5.1.10000-24.sgn.iso";
$finesseISO = "[datastore1] /ISOs/UCSInstall_FINESSE_12.5.1.10000-24.sgn.iso";
$cuicISO = "[datastore1] /ISOs/UCSInstall_CUIC_12_5_1_UCOS_12.5.1.10000-59.sgn.iso";
$vvbISO = "[datastore1] /ISOs/UCSInstall_VVB_12_5_1_UCOS_12.5.1.10000-24.sgn.iso";
$sideAGateway = "10.180.1.1";
$sideBGateway = "10.180.2.1";
$adSideAVMName = "AD-A.$domain";
$adSideAIPAddress = "10.180.1.200";
$adSideBVMName = "AD-B.$domain";
$adSideBIPAddress = "10.180.2.200";

$adVMs = @(
    @{computerName="CUCM-PUB-A"; productType="CUCM"; side = "A"; ipAddress = "10.180.1.211"; iso = $cucmISO; }
);





$ciscoVMs = @(
    @{computerName="CUCM-PUB-A"; productType="CUCM"; side = "A"; ipAddress = "10.180.1.211"; iso = $cucmISO; }
);

foreach ($ciscoVM in $ciscoVMs) {
    $numCPU = 1; $memoryGB = 5; $diskGB = 80; $networkName = "Private-Side" + $side;
    if (('FINESSE','CUIC').Contains($ciscoVM.$productType)) { $diskGB = 160; } # Finesse and CUIC need 160GB
    if ($ciscoVM.side -eq "A") { $adVMName = $adSideAVMName }

    Install-CiscoVM -esxiHost $esxiHost -vmName "$($ciscoVM.computerName).$domain" -productType "$($ciscoVM.productType)" -numCPU $numCPU -memoryGB $memoryGB -diskGB $diskGB -networkName $networkName -ciscoISOPath $iso `
        -adVMName $adVMName -adAdminPassword $password -computerName $ciscoVM.computerName -domain $domain -ipAddress "$ipPrefix.$($ciscoVM.ipSuffix)" -gatewayIP "$ipPrefix.1" -dnsIP "$ipPrefix.200" -adminPassword $password `
        -ntpIP "10.180.1.200" -securityPassword "P@ssword123!" -smtpIP "10.180.1.200" -appUserPassword $password -isFirstNode $true;
}




#Install-CiscoVM -esxiHost "192.168.1.199" -vmName "CUCM-PUB-A.JLAB1.LOCAL" -productType "CUCM" -numCPU 1 -memoryGB 5 -diskGB 80 -networkName "Private-SideA" -ciscoISOPath "[datastore1] /ISOs/cucm_UCSInstall_UCOS_12.5.1.12900-115.sgn_bootable.iso" `
#    -adVMName "AD-A.JLAB1.LOCAL" -adAdminPassword "P@ssword123!" -computerName "cucm-pub-a" -domain "jlab1.local" -ipAddress "10.180.1.211" -gatewayIP "10.180.1.1" -dnsIP "10.180.1.200" -adminPassword "P@ssword123!" `
#    -ntpIP "10.180.1.200" -securityPassword "P@ssword123!" -smtpIP "10.180.1.200" -appUserPassword "P@ssword123!" -isFirstNode $true;


#Install-CiscoVM -esxiHost "192.168.1.199" -vmName "CUCM-SUB-A.JLAB1.LOCAL" -productType "CUCM" -numCPU 1 -memoryGB 5 -diskGB 80 -networkName "Private-SideA" -ciscoISOPath "[datastore1] /ISOs/cucm_UCSInstall_UCOS_12.5.1.12900-115.sgn_bootable.iso" `
#    -adVMName "AD-A.JLAB1.LOCAL" -adAdminPassword "P@ssword123!" -computerName "cucm-sub-a" -domain "jlab1.local" -ipAddress "10.180.1.201" -gatewayIP "10.180.1.1" -dnsIP "10.180.1.200" -adminPassword "P@ssword123!" `
#    -ntpIP "10.180.1.200" -securityPassword "P@ssword123!" -smtpIP "10.180.1.200" -appUserPassword "P@ssword123!" -isFirstNode $false -firstNodeHostName "cucm-pub-a" -firstNodeIPAddress "10.180.1.211" -firstNodeVMName "CUCM-PUB-A.JLAB1.LOCAL";


#Install-CiscoVM -esxiHost "192.168.1.199" -vmName "FINESSE-A.JLAB1.LOCAL" -productType "FINESSE" -numCPU 1 -memoryGB 5 -diskGB 160 -networkName "Private-SideA" -ciscoISOPath "[datastore1] /ISOs/UCSInstall_FINESSE_12.5.1.10000-24.sgn.iso" `
#    -adVMName "AD-A.JLAB1.LOCAL" -adAdminPassword "P@ssword123!" -computerName "finesse-a" -domain "jlab1.local" -ipAddress "10.180.1.209" -gatewayIP "10.180.1.1" -dnsIP "10.180.1.200" -adminPassword "P@ssword123!" `
#    -ntpIP "10.180.1.200" -securityPassword "P@ssword123!" -smtpIP "10.180.1.200" -appUserPassword "P@ssword123!" -isFirstNode $true;


return






return;



Connect-VIServer -Server 192.168.1.199 -User root -Password P@ssword123!;

cd (Split-Path $MyInvocation.MyCommand.Path) # change directory to this script location
. .\_installFunctions2.ps1


Install-CiscoVM -esxiHost "192.168.1.199" -vmName "FINESSE-B.JLAB1.LOCAL" -productType "FINESSE" -numCPU 1 -memoryGB 4 -diskGB 160 -networkName "Private-SideB" -ciscoISOPath "[datastore1] /ISOs/UCSInstall_FINESSE_12.5.1.10000-24.sgn.iso" `
    -adVMName "AD-B.JLAB1.LOCAL" -adAdminPassword "P@ssword123!" -computerName "finesse-b" -domain "jlab1.local" -ipAddress "10.180.2.209" -gatewayIP "10.180.2.1" -dnsIP "10.180.2.200" -adminPassword "P@ssword123!" `
    -ntpIP "10.180.2.200" -securityPassword "P@ssword123!" -smtpIP "10.180.2.200" -appUserPassword "P@ssword123!" -isFirstNode $false -firstNodeHostName "finesse-a" -firstNodeIPAddress "10.180.1.209";


#Install-CiscoVM -esxiHost "192.168.1.199" -vmName "CUCM-SUB-A.JLAB1.LOCAL" -productType "CUCM" -numCPU 1 -memoryGB 4 -diskGB 80 -networkName "Private-SideA" -ciscoISOPath "[datastore1] /ISOs/cucm_UCSInstall_UCOS_12.5.1.12900-115.sgn_bootable.iso" `
#    -adVMName "AD-A.JLAB1.LOCAL" -adAdminPassword "P@ssword123!" -computerName "cucm-sub-a" -domain "jlab1.local" -ipAddress "10.180.1.201" -gatewayIP "10.180.1.1" -dnsIP "10.180.1.200" -adminPassword "P@ssword123!" `
#    -ntpIP "10.180.1.200" -securityPassword "P@ssword123!" -smtpIP "10.180.1.200" -appUserPassword "P@ssword123!" -isFirstNode $false -firstNodeHostName "cucm-pub-a" -firstNodeIPAddress "10.180.1.211";

#Install-CiscoVM -esxiHost "192.168.1.199" -vmName "CUIC-PUB-A.JLAB1.LOCAL" -productType "CUIC" -numCPU 1 -memoryGB 4 -diskGB 160 -networkName "Private-SideA" -ciscoISOPath "[datastore1] /ISOs/UCSInstall_CUIC_12_5_1_UCOS_12.5.1.10000-59.sgn.iso" `
#    -adVMName "AD-A.JLAB1.LOCAL" -adAdminPassword "P@ssword123!" -computerName "cuic-pub-a" -domain "jlab1.local" -ipAddress "10.180.1.205" -gatewayIP "10.180.1.1" -dnsIP "10.180.1.200" -adminPassword "P@ssword123!" `
#    -ntpIP "10.180.1.200" -securityPassword "P@ssword123!" -smtpIP "10.180.1.200" -appUserPassword "P@ssword123!" -isFirstNode $true;

#Install-CiscoVM -esxiHost "192.168.1.199" -vmName "FINESSE-A.JLAB1.LOCAL" -productType "FINESSE" -numCPU 1 -memoryGB 4 -diskGB 160 -networkName "Private-SideA" -ciscoISOPath "[datastore1] /ISOs/UCSInstall_FINESSE_12.5.1.10000-24.sgn.iso" `
#    -adVMName "AD-A.JLAB1.LOCAL" -adAdminPassword "P@ssword123!" -computerName "finesse-a" -domain "jlab1.local" -ipAddress "10.180.1.209" -gatewayIP "10.180.1.1" -dnsIP "10.180.1.200" -adminPassword "P@ssword123!" `
#    -ntpIP "10.180.1.200" -securityPassword "P@ssword123!" -smtpIP "10.180.1.200" -appUserPassword "P@ssword123!" -isFirstNode $true;

#Install-CiscoVM -esxiHost "192.168.1.199" -vmName "VVB-A.JLAB1.LOCAL"  -productType "VVB" -numCPU 1 -memoryGB 4 -diskGB 80 -networkName "Private-SideA" -ciscoISOPath "[datastore1] /ISOs/UCSInstall_VVB_12_5_1_UCOS_12.5.1.10000-24.sgn.iso" `
#    -adVMName "AD-A.JLAB1.LOCAL" -adAdminPassword "P@ssword123!" -computerName "vvb-a" -domain "jlab1.local" -ipAddress "10.180.1.201" -gatewayIP "10.180.1.1" -dnsIP "10.180.1.200" -adminPassword "P@ssword123!" `
#    -ntpIP "10.180.1.200" -securityPassword "P@ssword123!" -smtpIP "10.180.1.200" -appUserPassword "P@ssword123!" -isFirstNode $true;

#Send-VMKeystrokesText -vmName "FINESSE-PUB-A.JLAB1.LOCAL" -txt "yo<tab>10.1.1.1<tab>255.255.255.0<tab>10.1.1.2<tab><enter><2>" -description "name, IP, mask, gateway";
#Send-VMKeystrokesText -vmName "CUIC-PUB-A.JLAB1.LOCAL" -txt "yo<tab>10.1.1.1<tab>255.255.255.0<tab>10.1.1.2<tab><enter><2>" -description "name, IP, mask, gateway";
#Send-VMKeystrokesText -vmName "CUCM-SUB-A.JLAB1.LOCAL" -txt "yo<tab>10.1.1.1<tab>255.255.255.0<tab>10.1.1.2<tab><enter><2>" -description "name, IP, mask, gateway";
#Send-VMKeystrokesText -vmName "VVB-A.JLAB1.LOCAL" -txt "yo<tab>10.1.1.1<tab>255.255.255.0<tab>10.1.1.2<tab><enter><2>" -description "name, IP, mask, gateway";


#Send-VMKeystrokesText -vmName "FINESSE-PUB-A.JLAB1.LOCAL" -txt "4.4.4.4<tab><tab>test.local<tab><enter><2>" -description "dns ip, domain";
#Send-VMKeystrokesText -vmName "CUIC-PUB-A.JLAB1.LOCAL" -txt "4.4.4.4<tab><tab>test.local<tab><enter><2>" -description "dns ip, domain";
#Send-VMKeystrokesText -vmName "CUCM-SUB-A.JLAB1.LOCAL" -txt "4.4.4.4<tab><tab>test.local<tab><enter><2>" -description "dns ip, domain";
#Send-VMKeystrokesText -vmName "VVB-A.JLAB1.LOCAL" -txt "4.4.4.4<tab><tab>test.local<tab><enter><2>" -description "dns ip, domain";

#Send-VMKeystrokesText -vmName "FINESSE-PUB-A.JLAB1.LOCAL" -txt "administrator<tab>P@ssword123!<tab>P@ssword123!<tab><enter><2>" -description "dns ip, domain";
#Send-VMKeystrokesText -vmName "CUIC-PUB-A.JLAB1.LOCAL" -txt "administrator<tab>P@ssword123!<tab>P@ssword123!<tab><enter><2>" -description "dns ip, domain";
#Send-VMKeystrokesText -vmName "CUCM-SUB-A.JLAB1.LOCAL" -txt "administrator<tab>P@ssword123!<tab>P@ssword123!<tab><enter><2>" -description "dns ip, domain";
#Send-VMKeystrokesText -vmName "VVB-A.JLAB1.LOCAL" -txt "administrator<tab>P@ssword123!<tab>P@ssword123!<tab><enter><2>" -description "dns ip, domain";

#Send-VMKeystrokesText -vmName "FINESSE-PUB-A.JLAB1.LOCAL" -txt "Org<tab>Unit<tab>Location<tab>State<tab><tab><enter><2>" -description "dns ip, domain";
#Send-VMKeystrokesText -vmName "CUIC-PUB-A.JLAB1.LOCAL" -txt "Org<tab>Unit<tab>Location<tab>State<tab><tab><enter><2>" -description "dns ip, domain";
#Send-VMKeystrokesText -vmName "CUCM-SUB-A.JLAB1.LOCAL" -txt "Org<tab>Unit<tab>Location<tab>State<tab><tab><enter><2>" -description "dns ip, domain";
#Send-VMKeystrokesText -vmName "VVB-A.JLAB1.LOCAL" -txt "Org<tab>Unit<tab>Location<tab>State<tab><tab><enter><2>" -description "dns ip, domain";

#Send-VMKeystrokesText -vmName "FINESSE-PUB-A.JLAB1.LOCAL" -txt "P@ssword123!<tab>P@ssword123!<tab><enter><2>" -description "dns ip, domain";
#Send-VMKeystrokesText -vmName "CUIC-PUB-A.JLAB1.LOCAL" -txt "P@ssword123!<tab>P@ssword123!<tab><enter><2>" -description "dns ip, domain";
#Send-VMKeystrokesText -vmName "CUCM-SUB-A.JLAB1.LOCAL" -txt "P@ssword123!<tab>P@ssword123!<tab><enter><2>" -description "dns ip, domain";
#Send-VMKeystrokesText -vmName "VVB-A.JLAB1.LOCAL" -txt "P@ssword123!<tab>P@ssword123!<tab><enter><2>" -description "dns ip, domain";




#Send-VMKeystrokesText -vmName "AD-B.JLAB1.LOCAL" -txt "yo<tab>10.1.1.1<tab>255.255.255.0<tab>10.1.1.2<tab><enter><2>" -description "name, IP, mask, gateway";
#Send-VMKeystrokesText -vmName "AD-B.JLAB1.LOCAL" -txt "yo" -description "name, IP, mask, gateway";