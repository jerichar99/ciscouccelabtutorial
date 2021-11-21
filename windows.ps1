Set-PowerCLIConfiguration -InvalidCertificateAction Ignore -Confirm:$false > $null;
Connect-VIServer -Server 192.168.1.199 -User root -Password P@ssword123! > $null;

New-VM -Name "AD-A.JLAB1.LOCAL" -vmhost "192.168.1.199" -NumCpu 1 -MemoryGB 3 -DiskGB 50 -DiskStorageFormat Thin -GuestID windows7_64Guest -NetworkName "Private-SideA"; # guestID set to Win7 for firmware as BIOS not EFI
Get-VM "AD-A.JLAB1.LOCAL" | Set-VM -GuestId "windows9Server64Guest" -Confirm:$false;

New-CDDrive -VM "AD-A.JLAB1.LOCAL" -IsoPath "[datastore1] /ISOs/Windows_Server_2016_Datacenter_EVAL_en-us_14393_refresh.ISO" -StartConnected > $null;
New-CDDrive -VM "AD-A.JLAB1.LOCAL" -IsoPath "[datastore1] /ISOs/vmwaretools_windows.iso" -StartConnected > $null;
New-FloppyDrive -VM "AD-A.JLAB1.LOCAL" -FloppyImagePath "[datastore1] /floppies/windowsFloppy.flp" > $null; # note: don't start connected

Start-VM "AD-A.JLAB1.LOCAL";
Get-FloppyDrive -VM "AD-A.JLAB1.LOCAL" | Set-FloppyDrive -Connected:$true -Confirm:$false > $null;

