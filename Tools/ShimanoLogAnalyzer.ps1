# ShimanoLogAnalyzer.ps1 — GUI tool for analyzing Shimano UART logs
# Paste log lines (R:/R2:/B-TX:/B-RX:, with optional seq number), click Analyze.
#
# Decoded fields (cmd 0x10 telemetry, length=22):
#   [4]  Fault Byte   00=OK, 10=BMS-Lockout, 15=Auth-Failed/Degraded, 25=No-Cells
#   [5]  State        00=Init, 01=Active(motor), 02=Precharge, 03=Charge
#   [7]  Cell Conn    00=OK, 02=No-Cell-Conn (BMS lockout indicator)
#   [9..10]  Pack Voltage (mV, LE)
#   [11..12] Cell Vmax  (raw/2 = mV)
#   [13..14] Cell Vmin  (raw/2 = mV)
#   [15..17] NTC max / NTC avg / MOSFET temp (deg C)
#   [18]     SOC (%)
#   [19..21] Charger: ChgCtr/00/00 — Motor: 90 01 / discharge-current-raw
#
# Motor discharge current (offset 18 in payload, byte[21] in raw frame):
#   I_mA = 43 * byte + 58  (two-point calibration on BT-E6000, 2026-05-09)
#   Datapoints: byte=11 → 531 mA, byte=6 → 316 mA
#
# Polls (cmd 0x10 length=5) — payload byte[4]/[5]:
#   00 00  Charger          | 04 ..  Charger init/retry
#   02 02  Motor boot (bike) | 02 03  Motor boot (gregyedlik)
#   03 31  Motor first ready | 03 05  Motor steady (bike)
#   03 03  Motor (greg early)| 03 01  Motor steady (greg late)
#
# Auth (cmd 0x30): 02 01 = Charger flavor, 03 02 = Motor flavor.
#   Static replay of bytes captured from a real motor session works (battery
#   accepts → State=Active → MOSFETs released). Random bytes with the same
#   X/Y/X/Z structure are silently rejected. Inter-byte UART timing on the
#   sender side must include ~1-3 ms gaps — sending all bytes back-to-back
#   gets rejected (returns 2-byte degraded response, fault flips to 0x15).
# Cmd 0x12: Unknown command from gregyedlik's replay sequence.

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ---------- CRC-16/X-25 ----------
function Get-CRC16X25([byte[]]$data) {
    [uint16]$crc = 0xFFFF
    foreach ($b in $data) {
        $crc = $crc -bxor $b
        for ($i = 0; $i -lt 8; $i++) {
            if ($crc -band 1) {
                $crc = ($crc -shr 1) -bxor 0x8408
            } else {
                $crc = $crc -shr 1
            }
        }
    }
    return $crc -bxor 0xFFFF
}

# ---------- FIELD BACKGROUND COLORS ----------
$FIELD_COLORS = @{
    "structural" = [System.Drawing.Color]::FromArgb(220, 220, 220)
    "cmd"        = [System.Drawing.Color]::FromArgb(255, 215, 120)
    "state"      = [System.Drawing.Color]::FromArgb(210, 175, 255)
    "fault"      = [System.Drawing.Color]::FromArgb(255, 150, 150)
    "voltage"    = [System.Drawing.Color]::FromArgb(255, 255, 140)
    "cellmax"    = [System.Drawing.Color]::FromArgb(170, 235, 255)
    "cellmin"    = [System.Drawing.Color]::FromArgb(140, 195, 255)
    "temp"       = [System.Drawing.Color]::FromArgb(255, 190, 120)
    "soc"        = [System.Drawing.Color]::FromArgb(170, 255, 170)
    "chgctr"     = [System.Drawing.Color]::FromArgb(255, 240, 160)
    "current"    = [System.Drawing.Color]::FromArgb(255, 200, 100)
    "crc"        = [System.Drawing.Color]::FromArgb(200, 200, 200)
    "payload"    = [System.Drawing.Color]::FromArgb(240, 230, 200)
}

# ---------- HELPER: decode common bytes ----------
function Get-FaultName([int]$b) {
    switch ($b) {
        0x00 { return "OK" }
        0x10 { return "BMS-Lockout" }
        0x15 { return "Auth-Failed/Degraded" }
        0x25 { return "No-Cells" }
        default { return "0x$("{0:X2}" -f $b)" }
    }
}

function Get-CellConnName([int]$b) {
    switch ($b) {
        0x00 { return "OK" }
        0x02 { return "No-Cell-Conn" }
        default { return "0x$("{0:X2}" -f $b)" }
    }
}

function Get-PollName([int]$p1, [int]$p2) {
    if ($p1 -eq 0x00 -and $p2 -eq 0x00) { return "Charger" }
    if ($p1 -eq 0x02 -and $p2 -eq 0x02) { return "Motor boot (bike)" }
    if ($p1 -eq 0x02 -and $p2 -eq 0x03) { return "Motor boot (gregyedlik)" }
    if ($p1 -eq 0x03 -and $p2 -eq 0x31) { return "Motor ready (first)" }
    if ($p1 -eq 0x03 -and $p2 -eq 0x05) { return "Motor steady (bike)" }
    if ($p1 -eq 0x03 -and $p2 -eq 0x03) { return "Motor ready (gregyedlik early)" }
    if ($p1 -eq 0x03 -and $p2 -eq 0x01) { return "Motor steady (gregyedlik late)" }
    if ($p1 -eq 0x04) { return "Charger (init/retry flag)" }
    return "p1=0x$("{0:X2}" -f $p1) p2=0x$("{0:X2}" -f $p2)"
}

function Get-AuthFlavor([byte[]]$payload) {
    if ($payload.Count -lt 3) { return "?" }
    # payload[0] = cmd 0x30, payload[1..2] = format magic
    $m1 = $payload[1]; $m2 = $payload[2]
    if ($m1 -eq 0x03 -and $m2 -eq 0x02) { return "Motor" }
    if ($m1 -eq 0x02 -and $m2 -eq 0x01) { return "Charger" }
    return "Unknown"
}

# ---------- STRUCTURED PARSE ----------
function Parse-ShimanoMessage([string]$rawLine) {
    # Returns @{ Fields = list of @{N;V;S;E;C}; RawBytes; PrefixLen; Error }
    # N=Name, V=Value, S=ByteStart, E=ByteEnd, C=Color
    $r = @{ Fields = @(); RawBytes = @(); PrefixLen = 0; Error = "" }

    $t = $rawLine.Trim()
    if (-not $t) { $r.Error = "empty"; return $r }

    if ($t -match '^(\d+\s+)?(R2?:|B-[TR]X:)\s*') {
        $r.PrefixLen = $Matches[0].Length
    } else { $r.Error = "no prefix"; return $r }

    $hexPart = $t.Substring($r.PrefixLen)
    if ($hexPart -match '^([^|]+)') { $hexPart = $Matches[1].Trim() }

    $bytes = @()
    foreach ($tok in ($hexPart -split '\s+')) {
        if ($tok -match '^[0-9A-Fa-f]{2}$') { $bytes += [byte]([Convert]::ToByte($tok, 16)) }
    }
    $r.RawBytes = $bytes

    if ($bytes.Count -lt 5) { $r.Error = "too short"; return $r }
    if ($bytes[0] -ne 0x00) { $r.Error = "bad prefix"; return $r }

    $header = $bytes[1]; $seq = $header -band 0x0F
    $senderNibble = $header -band 0xF0
    $senderName = switch ($senderNibble) {
        0x00 { "Charger" }; 0x40 { "Charger (HS)" }; 0x80 { "Battery" }; 0xC0 { "Battery (HS)" }
        default { "0x$("{0:X2}" -f $senderNibble)" }
    }
    $length = $bytes[2]
    $total = 3 + $length + 2

    # CRC
    $crcText = "?"
    if ($bytes.Count -ge $total) {
        $crcLo = $bytes[$total-2]; $crcHi = $bytes[$total-1]
        $crcRx = [int]$crcLo + [int]$crcHi * 256
        if ($crcRx -eq 0) { $crcText = "CRC=0000 (ack)" }
        else {
            $crcCalc = Get-CRC16X25 $bytes[1..($total-3)]
            $crcText = if ($crcCalc -eq $crcRx) { "OK" } else { "ERROR" }
        }
    }

    $g = $FIELD_COLORS["structural"]
    $fields = [System.Collections.ArrayList]::new()
    $null = $fields.Add(@{N="Prefix"; V="0x00"; S=0; E=0; C=$g})
    $null = $fields.Add(@{N="Header"; V="$senderName Seq=$seq"; S=1; E=1; C=$g})
    $null = $fields.Add(@{N="Length"; V="$length"; S=2; E=2; C=$g})

    if ($length -eq 0) {
        $type = if ($senderNibble -eq 0x40 -or $senderNibble -eq 0xC0) { "Handshake" }
                else { $cv = [int]$bytes[3] + [int]$bytes[4] * 256; if ($cv -eq 0) { "Ack" } else { "Ping" } }
        $null = $fields.Add(@{N="Type"; V=$type; S=3; E=4; C=$g})
        $r.Fields = $fields; return $r
    }

    $cmd = $bytes[3]
    $null = $fields.Add(@{N="Command"; V="0x$("{0:X2}" -f $cmd)"; S=3; E=3; C=$FIELD_COLORS["cmd"]})

    if ($cmd -eq 0x10 -and $length -eq 22 -and $bytes.Count -ge 25) {
        $fault = $bytes[4]
        $state = $bytes[5]
        $cellConn = $bytes[7]
        $stName = switch ($state) { 0x00 {"Init"}; 0x01 {"Active"}; 0x02 {"Precharge"}; 0x03 {"Charging"}; default {"0x$("{0:X2}" -f $state)"} }
        $packV = [int]$bytes[9] + [int]$bytes[10] * 256
        $vMax = [int](([int]$bytes[11] + [int]$bytes[12] * 256) / 2)
        $vMin = [int](([int]$bytes[13] + [int]$bytes[14] * 256) / 2)
        $ntcM = $bytes[15]; $ntcA = $bytes[16]; $th = $bytes[17]
        $soc = $bytes[18]
        $b19 = $bytes[19]; $b20 = $bytes[20]; $b21 = $bytes[21]

        # offset 16-17 (bytes 19-20): motor=90 01, charger=ChgCtr in byte 19
        # offset 18 (byte 21): motor=current indicator, charger=00
        $isMotor = ($state -eq 0x01) -or ($b19 -eq 0x90 -and $b20 -eq 0x01)

        $faultColor = if ($fault -eq 0x00) { $g } else { $FIELD_COLORS["fault"] }
        $cellColor = if ($cellConn -eq 0x00) { $g } else { $FIELD_COLORS["fault"] }

        $null = $fields.Add(@{N="Fault Byte"; V="$(Get-FaultName $fault) (0x$("{0:X2}" -f $fault))"; S=4; E=4; C=$faultColor})
        $null = $fields.Add(@{N="State"; V="$stName (0x$("{0:X2}" -f $state))"; S=5; E=5; C=$FIELD_COLORS["state"]})
        $null = $fields.Add(@{N="Reserved 6"; V="0x$("{0:X2}" -f $bytes[6])"; S=6; E=6; C=$g})
        $null = $fields.Add(@{N="Cell Connection"; V="$(Get-CellConnName $cellConn) (0x$("{0:X2}" -f $cellConn))"; S=7; E=7; C=$cellColor})
        $null = $fields.Add(@{N="Reserved 8"; V="0x$("{0:X2}" -f $bytes[8])"; S=8; E=8; C=$g})
        $null = $fields.Add(@{N="Pack Voltage"; V="$packV mV ($("{0:N3}" -f ($packV/1000.0))V)"; S=9; E=10; C=$FIELD_COLORS["voltage"]})
        $null = $fields.Add(@{N="Vmax (per-cell)"; V="$vMax mV"; S=11; E=12; C=$FIELD_COLORS["cellmax"]})
        $null = $fields.Add(@{N="Vmin (per-cell)"; V="$vMin mV"; S=13; E=14; C=$FIELD_COLORS["cellmin"]})
        $null = $fields.Add(@{N="NTC max"; V="$ntcM C"; S=15; E=15; C=$FIELD_COLORS["temp"]})
        $null = $fields.Add(@{N="NTC avg"; V="$ntcA C"; S=16; E=16; C=$FIELD_COLORS["temp"]})
        $null = $fields.Add(@{N="MOSFET Temp"; V="$th C"; S=17; E=17; C=$FIELD_COLORS["temp"]})
        $null = $fields.Add(@{N="SOC"; V="$soc %"; S=18; E=18; C=$FIELD_COLORS["soc"]})
        if ($isMotor) {
            $null = $fields.Add(@{N="Motor Const (90 01)"; V="$("{0:X2}" -f $b19) $("{0:X2}" -f $b20)"; S=19; E=20; C=$FIELD_COLORS["chgctr"]})
            # Calibration 2026-05-09 (linear two-point): I_mA = 43 * byte[18] + 58
            $iMa = $b21 * 43 + 58
            $null = $fields.Add(@{N="Discharge Current"; V="${iMa} mA (raw=$b21, formula 43*x+58)"; S=21; E=21; C=$FIELD_COLORS["current"]})
        } else {
            $null = $fields.Add(@{N="Charge Counter"; V="$b19"; S=19; E=19; C=$FIELD_COLORS["chgctr"]})
            $null = $fields.Add(@{N="Reserved 20"; V="0x$("{0:X2}" -f $b20)"; S=20; E=20; C=$g})
            $null = $fields.Add(@{N="Reserved 21"; V="0x$("{0:X2}" -f $b21)"; S=21; E=21; C=$g})
        }
        $null = $fields.Add(@{N="Reserved 22-24"; V="..."; S=22; E=24; C=$g})
    } elseif ($cmd -eq 0x10 -and $length -eq 5) {
        $p1 = $bytes[4]; $p2 = $bytes[5]
        $null = $fields.Add(@{N="Poll"; V=(Get-PollName $p1 $p2); S=4; E=7; C=$FIELD_COLORS["payload"]})
    } elseif ($cmd -eq 0x30) {
        $authPayload = $bytes[3..(3+$length-1)]
        $flavor = Get-AuthFlavor $authPayload
        $null = $fields.Add(@{N="Auth ($flavor)"; V="$flavor flavor, $length B (cmd+payload)"; S=4; E=(3+$length-1); C=$FIELD_COLORS["payload"]})
    } elseif ($cmd -eq 0x31) {
        $null = $fields.Add(@{N="Specs"; V="Battery Specs ($length B)"; S=4; E=(3+$length-1); C=$FIELD_COLORS["payload"]})
    } elseif ($cmd -eq 0x11) {
        $null = $fields.Add(@{N="DevInfo"; V="Device Info ($length B)"; S=4; E=(3+$length-1); C=$FIELD_COLORS["payload"]})
    } elseif ($cmd -eq 0x12) {
        $null = $fields.Add(@{N="Cmd 0x12"; V="Unknown (gregyedlik replay; len=$length)"; S=4; E=(3+$length-1); C=$FIELD_COLORS["payload"]})
    } elseif ($cmd -eq 0x21) {
        $null = $fields.Add(@{N="Shutdown"; V="Shutdown ($length B)"; S=4; E=(3+$length-1); C=$FIELD_COLORS["payload"]})
    } elseif ($cmd -eq 0x32) {
        $null = $fields.Add(@{N="Trip"; V="Trip/Config ($length B; possibly date/time)"; S=4; E=(3+$length-1); C=$FIELD_COLORS["payload"]})
    } else {
        $null = $fields.Add(@{N="Payload"; V="Cmd 0x$("{0:X2}" -f $cmd) ($length B)"; S=4; E=(3+$length-1); C=$FIELD_COLORS["payload"]})
    }

    if ($bytes.Count -ge $total) {
        $null = $fields.Add(@{N="CRC"; V=$crcText; S=($total-2); E=($total-1); C=$FIELD_COLORS["crc"]})
    }

    $r.Fields = $fields
    return $r
}

# ---------- BUILD BYTE MAP ----------
function Build-ByteMap($parsed) {
    $map = @{}
    if ($parsed.Error) { return $map }
    foreach ($f in $parsed.Fields) {
        for ($i = $f.S; $i -le $f.E; $i++) { $map[$i] = $f }
    }
    return $map
}

# ---------- DECODE ----------
function Decode-ShimanoLine([string]$line) {
    $line = $line.Trim()
    if (-not $line) { return "" }

    # Extract channel prefix and hex bytes (optional leading seq number)
    $channel = ""
    $hexPart = $line
    if ($line -match '^(\d+\s+)?(R2?:|B-[TR]X:)\s*(.+)$') {
        $channel = $Matches[2]
        $hexPart = $Matches[3]
    } else {
        return "-- not a log line --"
    }

    # Channel label
    switch ($channel) {
        "R:"    { $chLabel = "Battery TX" }
        "R2:"   { $chLabel = "Charger/Motor TX" }
        "B-TX:" { $chLabel = "Battery TX" }
        "B-RX:" { $chLabel = "Charger/Motor TX" }
        default { $chLabel = $channel }
    }

    # Parse hex bytes
    $tokens = $hexPart.Trim() -split '\s+'
    $bytes = @()
    foreach ($t in $tokens) {
        $t = $t.Trim()
        if ($t -match '^[0-9A-Fa-f]{2}$') {
            $bytes += [byte]([Convert]::ToByte($t, 16))
        }
    }

    if ($bytes.Count -lt 5) {
        return "[$chLabel] Too short ($($bytes.Count) bytes)"
    }

    # Prefix
    $prefix = $bytes[0]
    if ($prefix -ne 0x00) {
        return "[$chLabel] Invalid prefix: 0x$("{0:X2}" -f $prefix)"
    }

    # Header
    $header = $bytes[1]
    $senderNibble = ($header -band 0xF0)
    $seq = ($header -band 0x0F)

    switch ($senderNibble) {
        0x00 { $sender = "Chg" }
        0x40 { $sender = "Chg(HS)" }
        0x80 { $sender = "Bat" }
        0xC0 { $sender = "Bat(HS)" }
        default { $sender = "0x$("{0:X2}" -f $senderNibble)" }
    }

    $length = $bytes[2]
    $expectedTotal = 3 + $length + 2

    # CRC check
    $crcOk = ""
    if ($bytes.Count -ge $expectedTotal) {
        $crcLo = $bytes[$expectedTotal - 2]
        $crcHi = $bytes[$expectedTotal - 1]
        $crcReceived = [int]$crcLo + [int]$crcHi * 256
        if ($crcReceived -eq 0) {
            $crcOk = "CRC=0000 (ack)"
        } else {
            $crcData = $bytes[1..($expectedTotal - 3)]
            $crcCalc = Get-CRC16X25 $crcData
            if ($crcCalc -eq $crcReceived) {
                $crcOk = "CRC OK"
            } else {
                $crcOk = "CRC ERROR (got $("{0:X4}" -f $crcReceived), calc $("{0:X4}" -f $crcCalc))"
            }
        }
    } elseif ($bytes.Count -lt $expectedTotal) {
        $crcOk = "INCOMPLETE ($($bytes.Count)/$expectedTotal bytes)"
    }

    # Length=0: Handshake / Ping / Ack
    if ($length -eq 0) {
        $type = ""
        if ($senderNibble -eq 0x40 -or $senderNibble -eq 0xC0) {
            $type = "Handshake"
        } else {
            # Check CRC
            $crcLo = $bytes[3]; $crcHi = $bytes[4]
            $crcVal = [int]$crcLo + [int]$crcHi * 256
            if ($crcVal -eq 0x0000) {
                $type = "Ack (CRC=0000)"
            } else {
                $type = "Ping"
            }
        }
        return "[$chLabel] ${sender}Seq=$seq | $type | $crcOk"
    }

    # Payload present
    $payload = $bytes[3..(3 + $length - 1)]
    $cmd = $payload[0]
    $cmdHex = "0x$("{0:X2}" -f $cmd)"

    # --- Cmd 0x10: Telemetry ---
    if ($cmd -eq 0x10) {
        # Poll (Length=5)
        if ($length -eq 5) {
            $pollByte1 = $payload[1]
            $pollByte2 = $payload[2]
            $pollInfo = "Poll: " + (Get-PollName $pollByte1 $pollByte2)
            return "[$chLabel] ${sender}Seq=$seq | $pollInfo | $crcOk"
        }

        # Telemetry response (Length=22)
        if ($length -eq 22 -and $payload.Count -ge 22) {
            $faultByte = $payload[1]
            $state     = $payload[2]
            $resv3     = $payload[3]
            $cellConn  = $payload[4]
            $resv5     = $payload[5]

            $packV     = [int]$payload[6] + [int]$payload[7] * 256
            $vMax      = [int](([int]$payload[8] + [int]$payload[9] * 256) / 2)
            $vMin      = [int](([int]$payload[10] + [int]$payload[11] * 256) / 2)
            $ntcMax    = $payload[12]
            $ntcAvg    = $payload[13]
            $th002     = $payload[14]
            $soc       = $payload[15]
            $b16       = $payload[16]
            $b17       = $payload[17]
            $b18       = $payload[18]

            switch ($state) {
                0x00 { $stName = "Init" }
                0x01 { $stName = "Active" }
                0x02 { $stName = "Precharge" }
                0x03 { $stName = "Charge" }
                default { $stName = "0x$("{0:X2}" -f $state)" }
            }

            $faultStr = "Fault=" + (Get-FaultName $faultByte)
            $cellStr2 = ""
            if ($cellConn -ne 0x00) { $cellStr2 = " CellConn=" + (Get-CellConnName $cellConn) }
            $resvInfo = ""
            if ($resv3 -ne 0 -or $resv5 -ne 0) { $resvInfo = " Resv3/5=$("{0:X2}" -f $resv3)/$("{0:X2}" -f $resv5)" }

            $voltStr = "$packV mV ($("{0:N3}" -f ($packV / 1000.0))V)"
            $cellStr = "Vmax=$vMax Vmin=$vMin"
            $tempStr = "T=$ntcMax/$ntcAvg/${th002}C"

            # Distinguish motor (90 01 + current) vs charger (ChgCtr) context.
            # Motor current calibration (2026-05-09 two-point linear fit on BT-E6000):
            #   I_mA = 43 * byte[18] + 58  (datapoints: 11→531mA, 6→316mA)
            $isMotor = ($state -eq 0x01) -or ($b16 -eq 0x90 -and $b17 -eq 0x01)
            if ($isMotor) {
                $iMa = $b18 * 43 + 58
                $extra = " | MotorConst=$("{0:X2}" -f $b16) $("{0:X2}" -f $b17) I=${iMa}mA (raw=$b18)"
            } else {
                $extra = " | ChgCtr=$b16 b17=$("{0:X2}" -f $b17) b18=$("{0:X2}" -f $b18)"
            }

            $result = "[$chLabel] ${sender}Seq=$seq | State=$stName | $faultStr$cellStr2$resvInfo | $voltStr | $cellStr | $tempStr | SOC=${soc}%$extra | $crcOk"
            return $result
        }

        # Other Length for Cmd 0x10
        $payloadHex = ($payload | ForEach-Object { "{0:X2}" -f $_ }) -join " "
        return "[$chLabel] ${sender}Seq=$seq | Cmd 0x10 Len=$length | $payloadHex | $crcOk"
    }

    # --- Cmd 0x12: Unknown (gregyedlik replay) ---
    if ($cmd -eq 0x12) {
        $payloadHex = ($payload | ForEach-Object { "{0:X2}" -f $_ }) -join " "
        return "[$chLabel] ${sender}Seq=$seq | Cmd 0x12 (unknown, gregyedlik replay) Len=$length | $payloadHex | $crcOk"
    }

    # --- Cmd 0x11: Device Info ---
    if ($cmd -eq 0x11) {
        if ($length -eq 1) {
            return "[$chLabel] ${sender}Seq=$seq | DevInfo Req | $crcOk"
        }
        if ($length -eq 9 -and $payload.Count -ge 9) {
            $payloadHex = ($payload | ForEach-Object { "{0:X2}" -f $_ }) -join " "
            $val1 = $payload[2]
            $fw1 = $payload[4]; $fw2 = $payload[5]
            return "[$chLabel] ${sender}Seq=$seq | DevInfo Resp | Byte2=0x$("{0:X2}" -f $val1) FW?=0x$("{0:X2}" -f $fw1)$("{0:X2}" -f $fw2) | $payloadHex | $crcOk"
        }
        $payloadHex = ($payload | ForEach-Object { "{0:X2}" -f $_ }) -join " "
        return "[$chLabel] ${sender}Seq=$seq | DevInfo Len=$length | $payloadHex | $crcOk"
    }

    # --- Cmd 0x21: Shutdown ---
    if ($cmd -eq 0x21) {
        if ($length -eq 1) {
            return "[$chLabel] ${sender}Seq=$seq | Shutdown Req | $crcOk"
        }
        if ($length -eq 3) {
            return "[$chLabel] ${sender}Seq=$seq | Shutdown Ack | $crcOk"
        }
        $payloadHex = ($payload | ForEach-Object { "{0:X2}" -f $_ }) -join " "
        return "[$chLabel] ${sender}Seq=$seq | Shutdown Len=$length | $payloadHex | $crcOk"
    }

    # --- Cmd 0x30: Authentication ---
    if ($cmd -eq 0x30) {
        $flavor = Get-AuthFlavor $payload
        $direction = if ($length -eq 17) { "Req" } elseif ($length -eq 18) { "Resp" } else { "Len=$length" }
        $payloadHex = ($payload | ForEach-Object { "{0:X2}" -f $_ }) -join " "
        return "[$chLabel] ${sender}Seq=$seq | Auth $direction ($flavor) | $payloadHex | $crcOk"
    }

    # --- Cmd 0x31: Battery Specs ---
    if ($cmd -eq 0x31) {
        $payloadHex = ($payload | ForEach-Object { "{0:X2}" -f $_ }) -join " "
        return "[$chLabel] ${sender}Seq=$seq | Specs Len=$length | $payloadHex | $crcOk"
    }

    # --- Cmd 0x32: Trip/Config ---
    if ($cmd -eq 0x32) {
        $payloadHex = ($payload | ForEach-Object { "{0:X2}" -f $_ }) -join " "
        return "[$chLabel] ${sender}Seq=$seq | Trip Len=$length | $payloadHex | $crcOk"
    }

    # --- Unknown command ---
    $payloadHex = ($payload | ForEach-Object { "{0:X2}" -f $_ }) -join " "
    return "[$chLabel] ${sender}Seq=$seq | Cmd $cmdHex Len=$length | $payloadHex | $crcOk"
}

# ---------- COLOR HELPER ----------
# Returns the display color for a log line based on channel prefix.
# Red = Charger/Request (R2: / B-RX:), Green = Battery/Answer (R: / B-TX:)
function Get-LineColor([string]$line) {
    $t = $line.Trim()
    if ($t -match '^(\d+\s+)?(R2:|B-RX:)') { return [System.Drawing.Color]::FromArgb(190, 0, 0) }
    if ($t -match '^(\d+\s+)?(R:|B-TX:)')  { return [System.Drawing.Color]::FromArgb(0, 140, 0) }
    return [System.Drawing.Color]::FromArgb(100, 100, 100)
}

# ---------- SELECTION STATE ----------
$script:selLineIdx = -1
$script:selByteMap = @{}
$script:selParsed  = $null

function Clear-ByteHighlights {
    if ($script:selLineIdx -lt 0 -or $script:selLineIdx -ge $txtInput.Lines.Count) { return }
    $start = $txtInput.GetFirstCharIndexFromLine($script:selLineIdx)
    if ($start -lt 0) { return }
    $len = $txtInput.Lines[$script:selLineIdx].Length
    if ($len -le 0) { return }
    $txtInput.Select($start, $len)
    $txtInput.SelectionBackColor = $txtInput.BackColor
}

function Apply-ByteHighlights($lineIdx, $byteMap, $prefixLen) {
    if ($lineIdx -lt 0 -or $byteMap.Count -eq 0) { return }
    $start = $txtInput.GetFirstCharIndexFromLine($lineIdx)
    if ($start -lt 0) { return }
    $lineLen = $txtInput.Lines[$lineIdx].Length
    foreach ($bi in $byteMap.Keys) {
        $off = $prefixLen + $bi * 3
        if (($off + 2) -gt $lineLen) { continue }
        $txtInput.Select($start + $off, 2)
        $txtInput.SelectionBackColor = $byteMap[$bi].C
    }
}

function Select-Line($lineIdx) {
    if ($lineIdx -lt 0 -or $lineIdx -ge $txtInput.Lines.Count) { return }
    Clear-ByteHighlights
    $raw = $txtInput.Lines[$lineIdx]
    $parsed = Parse-ShimanoMessage $raw
    $map = Build-ByteMap $parsed
    $script:selLineIdx = $lineIdx
    $script:selParsed  = $parsed
    $script:selByteMap = $map
    Apply-ByteHighlights $lineIdx $map $parsed.PrefixLen
    $txtInput.Select(0, 0)
}

# ---------- GUI ----------
$form = New-Object System.Windows.Forms.Form
$form.Text = "Shimano UART Log Analyzer"
$form.Size = New-Object System.Drawing.Size(1400, 700)
$form.StartPosition = "CenterScreen"
$form.MinimumSize = New-Object System.Drawing.Size(900, 400)
$form.Font = New-Object System.Drawing.Font("Segoe UI", 9)

# Top label
$lblInput = New-Object System.Windows.Forms.Label
$lblInput.Text = "Paste log lines (R:/R2:/B-TX:/B-RX:, optional seq number):"
$lblInput.Location = New-Object System.Drawing.Point(10, 8)
$lblInput.AutoSize = $true
$form.Controls.Add($lblInput)

$lblOutput = New-Object System.Windows.Forms.Label
$lblOutput.Text = "Decoded:"
$lblOutput.AutoSize = $true
$form.Controls.Add($lblOutput)

# Monospace font for text boxes
$monoFont = New-Object System.Drawing.Font("Consolas", 10)

# Input RichTextBox (left) — editable, colored after Analyze
$txtInput = New-Object System.Windows.Forms.RichTextBox
$txtInput.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Both
$txtInput.WordWrap = $false
$txtInput.Font = $monoFont
$txtInput.AcceptsReturn = $true
$txtInput.DetectUrls = $false
$form.Controls.Add($txtInput)

# Output RichTextBox (right) — read-only decoded output with colors
$txtOutput = New-Object System.Windows.Forms.RichTextBox
$txtOutput.ScrollBars = [System.Windows.Forms.RichTextBoxScrollBars]::Both
$txtOutput.WordWrap = $false
$txtOutput.Font = $monoFont
$txtOutput.ReadOnly = $true
$txtOutput.BackColor = [System.Drawing.Color]::FromArgb(245, 245, 245)
$txtOutput.DetectUrls = $false
$form.Controls.Add($txtOutput)

# Analyze button
$btnAnalyze = New-Object System.Windows.Forms.Button
$btnAnalyze.Text = "Analyze"
$btnAnalyze.Size = New-Object System.Drawing.Size(100, 30)
$btnAnalyze.Font = New-Object System.Drawing.Font("Segoe UI", 10, [System.Drawing.FontStyle]::Bold)
$btnAnalyze.BackColor = [System.Drawing.Color]::FromArgb(0, 120, 212)
$btnAnalyze.ForeColor = [System.Drawing.Color]::White
$btnAnalyze.FlatStyle = "Flat"
$form.Controls.Add($btnAnalyze)

# Clear button
$btnClear = New-Object System.Windows.Forms.Button
$btnClear.Text = "Clear"
$btnClear.Size = New-Object System.Drawing.Size(70, 30)
$btnClear.FlatStyle = "Flat"
$form.Controls.Add($btnClear)

# Status label
$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.AutoSize = $true
$lblStatus.ForeColor = [System.Drawing.Color]::Gray
$form.Controls.Add($lblStatus)

# Layout on resize
$form.Add_Resize({
    $w = $form.ClientSize.Width
    $h = $form.ClientSize.Height
    $btnY = 32
    $topOffset = 60
    $bottomMargin = 10
    $halfW = [Math]::Floor(($w - 30) / 2)
    $boxH = $h - $topOffset - $bottomMargin

    $txtInput.Location = New-Object System.Drawing.Point(10, $topOffset)
    $txtInput.Size = New-Object System.Drawing.Size($halfW, $boxH)

    $lblOutput.Location = New-Object System.Drawing.Point(($halfW + 20), 8)

    $txtOutput.Location = New-Object System.Drawing.Point(($halfW + 20), $topOffset)
    $txtOutput.Size = New-Object System.Drawing.Size($halfW, $boxH)

    $btnAnalyze.Location = New-Object System.Drawing.Point(($w - 300), $btnY)
    $btnClear.Location = New-Object System.Drawing.Point(($w - 190), $btnY)
    $lblStatus.Location = New-Object System.Drawing.Point(($w - 110), ($btnY + 6))
})

# Trigger initial layout
$form.Add_Shown({ $form.GetType().GetMethod('OnResize', [System.Reflection.BindingFlags]'NonPublic,Instance').Invoke($form, @([System.EventArgs]::Empty)) })

# Analyze click handler
$btnAnalyze.Add_Click({
    Clear-ByteHighlights
    $script:selLineIdx = -1; $script:selByteMap = @{}; $script:selParsed = $null
    $lines = $txtInput.Lines
    $txtOutput.Clear()

    $decoded = 0

    for ($i = 0; $i -lt $lines.Count; $i++) {
        $rawLine = $lines[$i]
        $trimmed = $rawLine.Trim()
        $color = Get-LineColor $rawLine

        # Color the input line (left side) — text unchanged
        $charStart = $txtInput.GetFirstCharIndexFromLine($i)
        if ($charStart -ge 0) {
            $txtInput.Select($charStart, $rawLine.Length)
            $txtInput.SelectionColor = $color
        }

        # Decode for the output line (right side)
        $result = if ($trimmed) { Decode-ShimanoLine $trimmed } else { "" }
        if ($result -and $result -ne "-- not a log line --") { $decoded++ }

        # Append colored decoded line to output
        $txtOutput.SelectionStart = $txtOutput.TextLength
        $txtOutput.SelectionColor = $color
        $suffix = if ($i -lt $lines.Count - 1) { "`n" } else { "" }
        $txtOutput.AppendText($result + $suffix)
    }

    # Deselect input text
    $txtInput.Select(0, 0)

    $lblStatus.Text = "$decoded lines decoded"
    $lblStatus.ForeColor = [System.Drawing.Color]::FromArgb(0, 120, 50)
})

# Clear click handler
$btnClear.Add_Click({
    $txtInput.Clear()
    $txtOutput.Clear()
    $lblStatus.Text = ""
    $script:selLineIdx = -1
    $script:selByteMap = @{}
    $script:selParsed = $null
    if ($popup.Visible) { $popup.Hide() }
})

# Right panel click: highlight byte groups on left
$txtOutput.Add_MouseDown({
    param($s, $e)
    if ($e.Button -ne [System.Windows.Forms.MouseButtons]::Left) { return }
    $ci = $txtOutput.GetCharIndexFromPosition($e.Location)
    $li = $txtOutput.GetLineFromCharIndex($ci)
    Select-Line $li
    $popup.Hide()
})

# ---------- POPUP (fixed position field info) ----------
$popup = New-Object System.Windows.Forms.Form
$popup.Text = "Field Info"
$popup.Size = New-Object System.Drawing.Size(440, 170)
$popup.FormBorderStyle = [System.Windows.Forms.FormBorderStyle]::FixedToolWindow
$popup.TopMost = $true
$popup.ShowInTaskbar = $false
$popup.StartPosition = [System.Windows.Forms.FormStartPosition]::Manual
$popup.KeyPreview = $true
$popup.Add_KeyDown({ param($s, $e) if ($e.KeyCode -eq [System.Windows.Forms.Keys]::Escape) { $popup.Hide() } })

$popupRtb = New-Object System.Windows.Forms.RichTextBox
$popupRtb.Dock = "Fill"
$popupRtb.ReadOnly = $true
$popupRtb.BorderStyle = "None"
$popupRtb.Font = New-Object System.Drawing.Font("Consolas", 11)
$popupRtb.DetectUrls = $false
$popupRtb.BackColor = [System.Drawing.Color]::FromArgb(252, 252, 245)
$popup.Controls.Add($popupRtb)

$monoBold = New-Object System.Drawing.Font("Consolas", 12, [System.Drawing.FontStyle]::Bold)

function Show-FieldPopup($field, $bytes) {
    $popupRtb.Clear()
    $popupRtb.SelectionBackColor = $field.C
    $popupRtb.SelectionFont = $monoBold
    $popupRtb.AppendText(" $($field.N) `n")
    $popupRtb.SelectionBackColor = $popupRtb.BackColor
    $popupRtb.SelectionFont = $popupRtb.Font
    $popupRtb.AppendText("`n")
    $popupRtb.AppendText("Value:  $($field.V)`n")
    $hex = ""
    for ($i = $field.S; $i -le $field.E; $i++) {
        if ($i -lt $bytes.Count) { $hex += "$("{0:X2}" -f $bytes[$i]) " }
    }
    $popupRtb.AppendText("Bytes:  [$($field.S)..$($field.E)]  $($hex.Trim())")

    $loc = $form.PointToScreen([System.Drawing.Point]::new($form.ClientSize.Width - 450, 65))
    $popup.Location = $loc
    if (-not $popup.Visible) { $popup.Show($form) }
    else { $popup.BringToFront() }
}

# Left panel click: select line + show popup for clicked byte group
$txtInput.Add_MouseDown({
    param($s, $e)
    if ($e.Button -ne [System.Windows.Forms.MouseButtons]::Left) { return }
    $ci = $txtInput.GetCharIndexFromPosition($e.Location)
    $li = $txtInput.GetLineFromCharIndex($ci)
    if ($li -ne $script:selLineIdx) {
        Select-Line $li
    }
    if ($script:selByteMap.Count -eq 0 -or -not $script:selParsed) { $popup.Hide(); return }
    $start = $txtInput.GetFirstCharIndexFromLine($li)
    $inLine = $ci - $start
    $afterPrefix = $inLine - $script:selParsed.PrefixLen
    if ($afterPrefix -lt 0) { $popup.Hide(); return }
    $bi = [Math]::Floor($afterPrefix / 3)
    if ($script:selByteMap.ContainsKey($bi)) {
        Show-FieldPopup $script:selByteMap[$bi] $script:selParsed.RawBytes
    } else {
        $popup.Hide()
    }
})

# Synchronized scrolling: scroll output when input scrolls
$scrolling = $false
$txtInput.Add_KeyUp({
    if (-not $scrolling) {
        $scrolling = $true
        $line = $txtInput.GetLineFromCharIndex($txtInput.GetCharIndexFromPosition([System.Drawing.Point]::new(0, 0)))
        $charIdx = $txtOutput.GetFirstCharIndexFromLine([Math]::Min($line, $txtOutput.Lines.Count - 1))
        if ($charIdx -ge 0) {
            $txtOutput.SelectionStart = $charIdx
            $txtOutput.ScrollToCaret()
        }
        $scrolling = $false
    }
})

[void]$form.ShowDialog()
$popup.Dispose()
