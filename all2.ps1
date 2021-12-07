$esxiHost = "192.168.1.199"
$esxiPassword = "P@ssword123!";
$publicNetwork = "Public Network";
$privateNetworkSideA = "Private-SideA";
$privateNetworkSideB = "Private-SideB";
$ipPrefixSideA = "10.180.1";
$ipPrefixSideB = "10.180.2";
$password = "P@ssword123!";
$domain = "JLAB1.LOCAL";

$isos = @{"WINDOWS" = "[datastore1] /ISOs/Windows_Server_2016_Datacenter_EVAL_en-us_14393_refresh.ISO";
          "VMWAREWINDOWS" = "[datastore1] /ISOs/vmwaretools_windows.iso";
          "CUCM" = "[datastore1] /ISOs/cucm_UCSInstall_UCOS_12.5.1.12900-115.sgn_bootable.iso";
          "VVB" = "[datastore1] /ISOs/UCSInstall_VVB_12_5_1_UCOS_12.5.1.10000-24.sgn.iso";
          "CUIC" = "[datastore1] /ISOs/UCSInstall_CUIC_12_5_1_UCOS_12.5.1.10000-59.sgn.iso";
          "FINESSE" = "[datastore1] /ISOs/UCSInstall_FINESSE_12.5.1.10000-24.sgn.iso";
          "FLOPPYWINDOWS" = "[datastore1] /floppies/windowsFloppy.flp";
          "VYOS" = "[datastore1] /ISOs/vyos-1.4-rolling-202108160117-amd64.iso";
          "CVP" = "[datastore1] /ISOs/UnifiedCVP_Installer_12_5_1_Build_325.iso";
          "CCE" = "[datastore1] /ISOs/CCEInst1251.iso";
          "SQL" = "[datastore1] /ISOs/SQLServer2017-x64-ENU-Dev.iso";
         };

$vms = @(
    @{name="ROUTER"; type="VYOS"; side = ""; iso = $isos["VYOS"]; }
    @{name="AD-A"; type="AD"; side = "A"; ip = "$ipPrefixSideA.200"; iso = $isos["WINDOWS"]; vmToolsISO = $isos["VMWAREWINDOWS"]; }
    @{name="CUCM-PUB-A"; type="CM_PUBLISHER"; side = "A"; ip = "$ipPrefixSideA.211"; iso = $isos["CUCM"]; }
    @{name="CUCM-SUB-A"; type="CM_SUBSCRIBER"; side = "A"; ip = "$ipPrefixSideA.201"; iso = $isos["CUCM"]; }
    @{name="AD-B"; type="AD"; side = "B"; ip = "$ipPrefixSideB.200"; iso = $isos["WINDOWS"]; vmToolsISO = $isos["VMWAREWINDOWS"]; }
    @{name="CUCM-SUB-B"; type="CM_SUBSCRIBER"; side = "B"; ip = "$ipPrefixSideB.201"; iso = $isos["CUCM"]; }
    @{name="CVP-A"; type="CVP"; side = "A"; ip = "$ipPrefixSideA.208"; iso = $isos["WINDOWS"]; vmToolsISO = $isos["VMWAREWINDOWS"]; }
    @{name="FINESSE-A"; type="FINESSE"; side = "A"; ip = "$ipPrefixSideA.209"; iso = $isos["FINESSE"]; }
    @{name="CUIC-A"; type="CUIC_PUBLISHER"; side = "A"; ip = "$ipPrefixSideA.205"; iso = $isos["CUIC"]; }
    @{name="FINESSE-B"; type="FINESSE"; side = "B"; ip = "$ipPrefixSideB.209"; iso = $isos["FINESSE"]; }
    @{name="CUIC-B"; type="CUIC_SUBSCRIBER"; side = "B"; ip = "$ipPrefixSideB.205"; iso = $isos["CUIC"]; }
    @{name="CVP-B"; type="CVP"; side = "B"; ip = "$ipPrefixSideB.208"; iso = $isos["WINDOWS"]; }
    @{name="AW-A"; type="CCE_AW"; side = "A"; ip = "$ipPrefixSideA.202"; iso = $isos["WINDOWS"]; }
    @{name="AW-B"; type="CCE_AW"; side = "B"; ip = "$ipPrefixSideB.202"; iso = $isos["WINDOWS"]; }
    @{name="PG-A"; type="CCE_PG"; side = "A"; ip = "$ipPrefixSideA.204"; iso = $isos["WINDOWS"]; }
    @{name="PG-B"; type="CCE_PG"; side = "B"; ip = "$ipPrefixSideB.204"; iso = $isos["WINDOWS"]; }
    @{name="ROGGER-A"; type="CCE_ROGGER"; side = "A"; ip = "$ipPrefixSideA.206"; iso = $isos["WINDOWS"]; }
    @{name="ROGGER-B"; type="CCE_ROGGER"; side = "B"; ip = "$ipPrefixSideB.206"; iso = $isos["WINDOWS"]; }
    @{name="VVB-A"; type="VVB"; side = "A"; ip = "$ipPrefixSideA.203"; iso = $isos["VVB"]; }
    @{name="VVB-B"; type="VVB"; side = "B"; ip = "$ipPrefixSideB.203"; iso = $isos["VVB"]; }
);

Connect-VIServer -Server $esxiHost -User root -Password $esxiPassword;
cd (Split-Path $MyInvocation.MyCommand.Path) # change directory to this script location
. .\_installFunctions3.ps1

foreach ($vm in $vms) {
    # if exists, skip
    if (Get-VM -Name $vm.name -ErrorAction SilentlyContinue) { Write-Host "Skipping already created VM $($vm.name)"; Continue; }

    $networkName = if ($vm.side -eq "A") { $privateNetworkSideA } else { $privateNetworkSideB }; # except VyOS
    $ipPrefix = if ($vm.side -eq "A") { $ipPrefixSideA } else { $ipPrefixSideB };
    $vmAD = $vms.Where({$PSItem.side -eq $vm.side -and $PSItem.type -eq "AD"}); # AD-A or AD-B

    if ($vm.type -eq "VYOS") {
        Install-VyOSVM -esxiHost $esxiHost -vmName $vm.name -numCPU 1 -memoryGB 0.5 -diskGB 2 -iso $vm.iso -networkNames @($publicNetwork, $privateNetworkSideA, $privateNetworkSideB) -ipPrefixSideA $ipPrefixSideA -ipPrefixSideB $ipPrefixSideB
    }
    elseif (('AD', 'CVP').Contains($vm.type) -or $vm.type.Substring(0, 3) -eq "CCE") { # Windows (AD, CVP, CCE)
        $numCPU = 1; $memoryGB = 4; $diskGB = 50; $dnsIP = $vmAD.ip; $secondDiskGB = $null;
        Install-WindowsVM -esxiHost $esxiHost -vmName $vm.name -numCPU $numCPU -memoryGB $memoryGB -diskGB $diskGB -networkName $networkName -windowsISOPath $vm.iso -vmwareToolsISOPath $isos["VMWAREWINDOWS"] -floppyPath $isos["FLOPPYWINDOWS"];

        if ($vm.type -eq "AD" -and $vm.side -eq "B") { $dnsIP = $vms.Where({$PSItem.side -eq 'A' -and $PSItem.type -eq "AD"}).ip; } # side B AD is and exception, where its DNS points to side A AD
        Set-WindowsVMNetwork -vmName $vm.name -adminPassword $password -computerName $vm.name -ipAddress $vm.ip -gatewayIP "$ipPrefix.1" -dnsIP $dnsIP;

        if ($vm.type -eq "AD") {
            Create-WindowsDomain -vmName $vm.name -adminPassword $password -domain $domain -domainPassword $password -isNewForest ($vm.side -eq "A");
            Finish-WindowsAD -vmName $vm.name -adminPassword $password -reverseZone "$ipPrefix.0/24";
        }
        else { # CCE or CVP
            Join-WindowsDomain -vmName $vm.name -adminPassword $password -domain $domain -domainPassword $password;
            if ($vm.type -eq "CVP") {
                Finish-WindowsCVP -vmName $vm.name -adminPassword $password -cvpISOPath $isos["CVP"] -cvpPassword $password;
            }
            else {
                Finish-WindowsCCE -vmName $vm.name -adminPassword $password -type $vm.type -side $vm.side -sqlISOPath $isos["SQL"] -cceISOPath $isos["CCE"] -sqlPassword $password -domain $domain;
            }
        }
    }
    else { # Cisco
        $numCPU = 1; $memoryGB = 5; $diskGB = 80;
        if ($vm.type -like 'FINESSE' -or $vm.type -like 'CUIC*') { $diskGB = 160; } # Finesse and CUIC need 160GB
        $vmPub = $vms.Where({$PSItem.side -eq 'A' -and $vm.type.Replace("SUBSCRIBER", "PUBLISHER") -eq $PSItem.type}); # CM_SUBSCRIBER=>CM_PUBLISHER, FINESSE=>FINESSE

        Install-CiscoVM -esxiHost $esxiHost -vmName $vm.name -productType $vm.type -numCPU $numCPU -memoryGB $memoryGB -diskGB $diskGB -networkName $networkName -ciscoISOPath $vm.iso `
            -adVMName $vmAD.name -adAdminPassword $password -computerName $vm.name -domain $domain -ipAddress $vm.ip -gatewayIP "$ipPrefix.1" -dnsIP $vmAD.ip -adminPassword $password `
            -ntpIP $vmAD.ip -securityPassword $password -smtpIP $vmAD.ip -appUserPassword $password `
            -isFirstNode ($vm.side -eq "A" -and $vm.type -notlike "*SUBSCRIBER") -firstNodeHostName $vmPub.name -firstNodeIPAddress $vmPub.ip -firstNodeVMName $vmPub.name;
    }
}

# ------------- once all machines are installed --------------------------

$facilityName = "fac1";
$instanceName = "inst1";

# 1) run domain manager on any CCE machine
$aw_a = $vms.Where({$PSItem.type -eq "CCE_AW" -and $PSItem.side -eq 'A'}); # pick AW side A
#Run-DomainManager -vmName $aw_a.name -adminPassword $password -facilityName $facilityName -instanceName $instanceName -domain $domain;

# 2) import all certs
$cvp_cces = $vms.Where({$PSItem.type -like '*CVP*' -or $PSItem.type -like '*CCE*'});
#foreach ($vm in $cvp_cces) {
#    Import-Certs -vmName $vm.name -adminPassword $password -vms $vms -domain $domain; }

# 3) optional: customize Windows
$windowsVMs = $vms.Where({$PSItem.type -like '*CVP*' -or $PSItem.type -like '*CCE*' -or $PSItem.type -like '*AD*'});
#foreach ($vm in $windowsVMs) {
#    Send-VMKeystrokesText -vmName $vm.name -txt "<#r><1>powershell -command `"& { . A:\functions.ps1; Customize-Explorer; Install-CommonPrograms; }`"<1><enter><10>" -description "run customizations for $($vm.name)"; }

# 4) create inventory.csv
#Create-InventoryCSV -esxiHost $esxiHost -vms $vms -password $password -domain $domain -outputFile ".\inventory.csv";

# start/stop VMs in order with 120 seconds gap
#foreach ($vm in ($vms | Sort-Object -Descending {(++$script:i)})) { Shutdown-VMGuestDelayed -vmName $vm.name -delay 60; } # reverse order
#foreach ($vm in $vms) { Start-VMDelayed -vmName $vm.name -delay 120; }