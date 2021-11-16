function Sleep-Countdown { param($msg, $seconds) For ($i=$seconds; $i -gt 0; $i--) { Write-Progress -Activity $msg -SecondsRemaining $i; Start-Sleep 1 } }

# vmGV from Get-View, $hidCode "0x4f" right arrow, "0x50" left arrow, "0x28" enter, see https://gist.github.com/MightyPork/6da26e382a7ad91b5496ee55fdc73db2
# Send-VMKeystrokes -vmGV $vmGV -hidCode "0x4f"
function Send-VMKeystroke { param($vmGV, [string]$hidCode, $leftAlt, $leftShift)
    $tmp = New-Object VMware.Vim.UsbScanCodeSpecKeyEvent -Property @{ UsbHidCode = ([Convert]::ToInt64($hidCode, "16") -shl 16) -bor 0007 };
    $tmp.Modifiers = (New-Object Vmware.Vim.UsbScanCodeSpecModifierType -Property @{ LeftAlt = $leftAlt; LeftShift = $leftShift });
    $spec = New-Object Vmware.Vim.UsbScanCodeSpec -Property @{ KeyEvents = $tmp};
    $vmGV.PutUsbScanCodes($spec) > $null;
    Sleep -Milliseconds 50;
}

function Send-VMKeystrokes { param($vmGV, [string[]] $hidCodes)
    foreach($hidCode in $hidCodes) {
        Send-VMKeystroke -vmGV $vmGV -hidCode $hidCode; }
}

# sends keyboard presses into the VM, using a complicated mapping of characters to USB HID scan codes
# note: not exhaustive mapping, more characters can be added
# Send-VMKeystrokesText -vmName "ROUTER.JLAB1.LOCAL" -txt "myPassword" will type "m y P a s s w o r d" into the VM session
# note: | character is return + 2 second wait, ~ is 5 second wait
function Send-VMKeystrokesText { param($vmName, [string]$txt)
    $vmGV = Get-View -ViewType VirtualMachine -Filter @{"Name" = $vmName };

    $chars = $txt.ToCharArray();
    # loop through each character in $txt
    foreach ($char in $chars) {
        if ($char -eq '~') { Sleep -Seconds 5; continue; } # wait 5 seconds and continue
        $asciiCode = [byte][char]$char;
        $shift = $false; $hidCode = "";
        if ($asciiCode -ge ([byte][char]'a') -and $asciiCode -le ([byte][char]'z')) { # a-z
            $hidCode = [byte][char]$char - 93; # a=4, b=5...z=29
        } elseif ($asciiCode -ge ([byte][char]'A') -and $asciiCode -le ([byte][char]'Z')) { # A-Z
            $hidCode = [byte][char]$char - 61; # same codes as a-z, but with shift
            $shift = $true;
        } elseif ($asciiCode -ge ([byte][char]'1') -and $asciiCode -le ([byte][char]'9')) { # 1-9
            $hidCode = [byte][char]$char - 19; # 1=30, 2=31...9=38
        }
        else { # no pattern with these characters, just a lookup table (some with shifts)
            # note:  will be "return" 0x28/40
            $hidCode = switch ($char) { '"' { $shift = $true; 52 } '''' { 52 } '|' { 40 } ' ' { 44 } '0' { 39 } '!' { $shift = $true; 30 } '@' { $shift = $true; 31 } '#' { $shift = $true; 32 } '$' { $shift = $true; 33 } '%' { $shift = $true; 34 } '^' { $shift = $true; 35 } '&' { $shift = $true; 35 } '*' { $shift = $true; 36 } '(' { $shift = $true; 37 } ')' { $shift = $true; 38 } '_' { $shift = $true; 45 } '+' { $shift = $true; 46 } '\' { 49 } '-' { 45 } '.' { 55 } '/' { 56 } ':' { $shift = $true; 51 } ';' { 51 } '<' { $shift = $true; 54 } '<' { $shift = $true; 55 } '?' { $shift = $true; 56 } '[' { 47 } ']' { 48 } '{' { $shift=$true; 47 } '}' { $shift=$true; 48 }   }
        }
        # convert number to hex (e.g. 4 => 0x04, 31 => 0x1F)
        $hidCodeHex = "0x"+([byte][char]$hidCode).ToString("X2");
        Send-VMKeystroke -vmGV $vmGV -hidCode $hidCodeHex -leftAlt $false -leftShift $shift;
        if ($char -eq '|') { Sleep -Seconds 2; } # wait 2 seconds and continue
    }
}
