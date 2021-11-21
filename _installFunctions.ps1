function Sleep-Countdown { param($msg, $seconds) For ($i=$seconds; $i -gt 0; $i--) { Write-Progress -Activity $msg -SecondsRemaining $i; Start-Sleep 1 } }

# vmGV from Get-View, $hidCode "0x4f" right arrow, "0x50" left arrow, "0x28" enter, see https://gist.github.com/MightyPork/6da26e382a7ad91b5496ee55fdc73db2
# Send-VMKeystrokes -vmGV $vmGV -hidCode "0x4f"
function Send-VMKeystroke { param($vmGV, [string]$hidCode, $leftAlt, $leftShift, $leftControl)
    $tmp = New-Object VMware.Vim.UsbScanCodeSpecKeyEvent -Property @{ UsbHidCode = ([Convert]::ToInt64($hidCode, "16") -shl 16) -bor 0007 };
    $tmp.Modifiers = (New-Object Vmware.Vim.UsbScanCodeSpecModifierType -Property @{ LeftAlt = $leftAlt; LeftShift = $leftShift; LeftControl = $leftControl; });
    $spec = New-Object Vmware.Vim.UsbScanCodeSpec -Property @{ KeyEvents = $tmp};
    $vmGV.PutUsbScanCodes($spec) > $null;
    #Sleep -Milliseconds 50;
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
