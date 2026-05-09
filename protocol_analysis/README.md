# Protocol Analysis: Shimano E-Bike UART Communication
Generated via ClaudeAI

## Overview

Analysis of the UART communication on a Shimano e-bike system:
- **Charger ↔ Battery**: EC-E6002 charger and BT-E6000 battery
- **Motor/Display ↔ Battery**: Motor DU-E6012 and display SC-E6010 communicating with BT-E6000

Battery: 36V, 10S4P Li-Ion, 418Wh.
Data captured via dual-channel UART sniffing on the bus (battery TX line + charger/motor TX line). Earlier captures used a Raspberry Pi setup; newer captures use an ESP32-based logger.

## Bus Topology

Two-wire UART (8N1, 9600 baud) — separate TX/RX lines, not shared half-duplex.

| Channel | Wire | Device | Sender Addresses |
|---------|------|--------|------------------|
| CH1 (`R:` / `B-TX:`) | Battery TX → Charger/Motor RX | Battery (BT-E6000/E6001) | 0x80, 0xC0 |
| CH2 (`R2:` / `B-RX:`) | Charger/Motor TX → Battery RX | Charger (EC-E6002) or Motor/Display (DU-E6012/SC-E6010) | 0x00, 0x40 |

The two wires are physically distinct (not a shared bus). Both Charger and Motor share the same 0x00/0x40 sender address space — they are never connected to the battery simultaneously. Older capture logs use `R:`/`R2:` channel labels; newer logs use `B-TX:`/`B-RX:`. Both refer to the same wires.

UART config: **9600 baud, 8 data bits, no parity, 1 stop bit (8N1)**.

## Message Frame Format

```
[PREFIX] [HEADER] [LENGTH] [PAYLOAD...] [CRC16-LO] [CRC16-HI]
  0x00    1 byte   1 byte   N bytes       2 bytes (x-25)
```

- **PREFIX**: Always `0x00`
- **HEADER**: Upper nibble = sender address, lower nibble = sequence number (0–3)
- **LENGTH**: Number of payload bytes
- **CRC**: CRC-16/X-25 (little-endian), calculated over HEADER + LENGTH + PAYLOAD. A CRC of `0x0000` is treated as "no CRC" and always passes.

## Communication Flow

### 1. Handshake

Either device can initiate the handshake. The handshake sequence number increments across sessions independently from the telemetry sequence number.

```
Battery → 00 C1 00 35 DC       Ping (Sender=0xC0, Seq=1, Length=0, CRC valid)
Charger → 00 41 00 F9 50       Pong (Sender=0x40, Seq=1, Length=0, CRC valid)
```

#### Cold-wake from deep sleep

When the BMS is fully asleep, just opening UART is not sufficient — the MCU is unpowered until it sees a sustained 3.3V on the battery's RX pin (transistor wake circuit). Empirical wake sequence observed:

1. Hold battery RX line at **3.3V (UART idle HIGH)** for ~6 seconds
2. Within that window, send 3 raw handshake bursts `00 40 00 21 49` at approximately T+280ms, T+480ms, T+680ms
3. After the 3rd burst, the battery's MCU bootstraps and sends its own spontaneous `00 C0 00 ED C5` Ping
4. From that point, the normal protocol can proceed

This wake also fires when the user presses the SoC indicator button on the battery side, or the bike's PowerON button — both create the same 3.3V pulse on the battery's RX pin.

### 2. Charger Startup Commands

After the handshake, the charger exchanges two commands before starting telemetry polls. Captured 2026-04-12 with dual-channel ordered output ([full log](logs/2026-04-12_charger_dual_channel.log)).

**Full charger startup sequence:**
```
1. Handshake:   R2: 00 42 00 91 7A        →  R: 00 C2 00 5D F6
2. Cmd 0x30:    R2: 00 03 11 30 02 01 ... →  R: 00 83 12 30 00 ...      (authentication)
3. Cmd 0x31:    R2: 00 00 0B 31 9E 01 ... →  R: 00 80 12 31 00 9F 01 ... (battery specs)
4. First poll:  R2: 00 01 05 10 00 ...     →  R: 00 81 16 10 ... State=0x00 (Init)
5. Precharge:   R2: 00 02 05 10 00 ...     →  R: 00 82 16 10 ... State=0x02
6. Charging:    R2: 00 00 05 10 00 ...     →  R: 00 80 16 10 ... State=0x03
7. Steady:      Every poll → full telemetry response
```

#### Cmd 0x30 — Authentication (Length=17 request, Length=18 response)

The charger/motor sends a 17-byte challenge; the battery responds with 18 bytes. Both the challenge and response data change every session — consistent with a cryptographic authentication handshake.

**Two flavors observed**, distinguished by payload bytes 1–2:
- **Charger**: payload starts `30 02 01 ...` (cmd echo `30`, magic `02 01`)
- **Motor**: payload starts `30 03 02 00 00 ...` (cmd echo `30`, magic `03 02 00 00`)

```
Charger session 1:
R2: 00 03 11 30 02 01 12 77 4F 29 1F 48 4F 59 7A D9 F8 0D 6B 04 F7 0D
R:  00 83 12 30 00 BF 6B C1 2E 2F 61 9B E1 26 33 92 FD EE 4A C8 D1 CB B3

Charger session 2 (reconnect):
R2: 00 03 11 30 02 01 20 19 04 E5 2C 6C A6 12 7C D8 1E 3B 22 04 2E E8
R:  00 83 12 30 00 CF AB 96 7F 00 33 23 61 B2 8F AA 2C 10 3F EB 38 37 11

Motor session A (BT-E6000):
R2: 00 01 11 30 03 02 00 00 CB 72 1A 01 4B 2E CB 72 1A 01 2E 03 BE 18
R:  00 81 12 30 00 38 A2 05 89 19 32 01 77 1A 5F 06 C7 50 7A 4D 8A 5F 8D

Motor session B (BT-E6000, same boot, after off/on):
R2: 00 01 11 30 03 02 00 00 73 1B 02 4C 2F CC 73 1B 02 4C B8 02 F1 54
R:  00 81 12 30 00 1B B5 1E 1A A7 C0 10 80 4D 13 FD EF 36 AF 66 C0 82 AC
```

**Motor Auth-Req payload structure** (16 bytes after cmd 0x30):

| Bytes | Field | Notes |
|-------|-------|-------|
| 0–3 | `03 02 00 00` | Constant header / magic |
| 4–7 | X (4 bytes) | Random challenge — changes every session |
| 8–9 | Y (2 bytes) | Random field — changes per session |
| 10–13 | X (4 bytes) | Repeat of bytes 4–7 (verification echo) |
| 14–15 | Z (2 bytes) | Random field — changes per session |

The X-block always repeats verbatim at offsets 4–7 and 10–13 — this is structural validation the battery checks. The Y and Z fields appear cryptographically random.

**Validation behavior** (verified empirically 2026-05-09 with ESP32 simulator):

The battery's auth check has two distinct components, both must pass:

1. **Inter-byte UART timing fingerprint**: When transmitting Auth-Req (or any frame to the battery), the sender must use ~1–3 ms gaps between bytes. Sending all bytes back-to-back (e.g., via a single `serialWriteBytes(buf, len)` on ESP32 or `ser.write(bytes_string)` on Pi) — even with structurally and CRC-valid bytes — gets silently rejected. The battery returns a degraded 2-byte response `00 8X 02 30 12 ..` (status `0x12`) and after ~8s flips Status byte[4] to `0x15` (Auth-Failed/Degraded), refusing transition to Active state. Sending each byte individually with `delayMicroseconds(2500)` between bytes fixes this — the battery returns the full 18-byte cryptographic Auth-Resp and proceeds normally. The original gregyedlik script works because Python `ser.write(byte)` per byte naturally inserts ~ms-level gaps; a Python variant that batches the entire burst into one `ser.write(buffer)` reproduces the failure.

2. **Replay vs random**: Even with correct byte timing, **arbitrary random bytes with the right X/Y/X/Z structure are still rejected**. The battery accepts only Auth-Req payloads it has seen from a real motor before — empirically, replaying any of:
   - gregyedlik's captured bytes (`X=3D 83 35 E9, Y=97 51, Z=A9 04`)
   - bytes captured from the same battery's previous bike sessions (`X=CB 72 1A 01, Y=4B 2E, Z=2E 03` and `X=73 1B 02 4C, Y=2F CC, Z=B8 02`)

   all work — battery returns valid 17-byte Auth-Resp. Random bytes return the 2-byte `30 12` degraded response. This suggests either (a) a small set of "blessed" challenge values stored in the BMS, or (b) the motor's MCU computes both the challenge and an embedded MAC the battery validates. Without firmware reverse engineering the algorithm is unknown, but **static replay of known-working bytes is sufficient for full motor simulation including MOSFET activation**.

Battery's Auth-Resp content is also cryptographic. The motor/charger does **not** validate the response — both real Pi-based and simulated ESP32 setups proceed normally regardless of response content, suggesting the auth handshake is one-way (battery validates motor) rather than mutual.

michielvg's register scan with a simple 2-byte request (`30 00`) returned only a 2-byte response (`12`). The full 17-byte charger request is required to trigger the 18-byte authentication response.

#### Cmd 0x31 — Battery Specifications (Length=11 request, Length=18 response)

Static exchange — identical across sessions. The charger sends capacity parameters; the battery responds with its own specifications.

```
R2: 00 00 0B 31 9E 01 A5 01 01 00 05 00 10 00 5E B2
R:  00 80 12 31 00 9F 01 A9 01 01 00 05 00 28 00 6E 00 D8 01 78 00 6D 4B
```

| Offset | Type | Request | Response | Notes |
|--------|------|---------|----------|-------|
| 0 | uint8 | `31` | `31` | Cmd echo |
| 1 | — | — | `00` | Status (OK) |
| 1–2 / 2–3 | LE uint16 | 414 (0x019E) | 415 (0x019F) | Close to rated 418 Wh — remaining capacity? |
| 3–4 / 4–5 | LE uint16 | 421 (0x01A5) | 425 (0x01A9) | Design capacity? |
| 5 / 6 | uint8 | 1 | 1 | Unknown |
| 6 / 7 | uint8 | 0 | 0 | Unknown |
| 7–8 / 8–9 | LE uint16 | 5 | 5 | Unknown (cell groups? protocol version?) |
| 9–10 | LE uint16 | 16 (0x10) | — | Request-only field |
| 10–11 | LE uint16 | — | 40 (0x28) | Max charge current? (4.0A with 0.1A unit?) |
| 12–13 | LE uint16 | — | 110 (0x6E) | Unknown |
| 14–15 | LE uint16 | — | 472 (0x01D8) | Unknown |
| 16–17 | LE uint16 | — | 120 (0x78) | Unknown |

michielvg's register scan timed out on Cmd 0x31 — it requires the full 11-byte charger request, not just a 2-byte probe.

### 3. Charger Poll — Cmd 0x10 (Length=5)

The charger continuously polls the battery at ~1 second intervals, cycling through sequence numbers 0–3:

```
Charger → 00 00 05 10 00 00 00 00 B7 2C    Seq=0
Charger → 00 01 05 10 00 00 00 00 62 B3    Seq=1
Charger → 00 02 05 10 00 00 00 00 0C 1B    Seq=2
Charger → 00 03 05 10 00 00 00 00 D9 84    Seq=3
```

Payload is always `10 00 00 00 00` — Cmd 0x10 followed by 4 zero bytes. The charger is a "dumb" power supply; all charging logic resides in the battery.

### 4. Battery Telemetry Response — Cmd 0x10 (Length=22)

During active charging (State 0x03), the battery responds to **every** charger poll with a full 22-byte telemetry message. State transitions: Init (1 poll) → Precharge (1–2 polls) → Charging (continuous).

Earlier single-channel captures suggested telemetry only at specific moments with ack pairs in between. Dual-channel ordered output (2026-04-12) reveals this was an artifact of missed CH2 data — the battery actually responds to every poll.

See [dual-channel charger log](logs/2026-04-12_charger_dual_channel.log), [5x connect/disconnect log](logs/2026-03-28_0850_5x_connect_disconnect.log).

Example response:
```
Battery → 00 80 16 10 00 03 00 00 00 F7 95 04 1E FC 1D 16 15 16 3D 12 00 00 00 00 00 87 F1
```

#### Byte-by-byte breakdown

| Byte(s) | Hex | Field | Value |
|---------|-----|-------|-------|
| 0 | `00` | PREFIX | Always 0x00 |
| 1 | `80` | HEADER | Upper nibble = sender address (0x80 = Battery), lower nibble = sequence number (0 here). Seq cycles 0→1→2→3→0 across successive messages. |
| 2 | `16` | LENGTH | 22 payload bytes |
| 3 | `10` | Cmd (offset 0) | 0x10 (Telemetry) |
| 4 | `00` | Status / Fault Byte (offset 1) | 0x00=OK; 0x10=BMS-Lockout; 0x15=Auth-Failed/Degraded; 0x25=No-Cells |
| 5 | `03` | State (offset 2) | 0x00=Init, 0x01=Active (motor), 0x02=Precharge, 0x03=Charging |
| 6 | `00` | Reserved (offset 3) | Always 0x00 |
| 7 | `00` | Cell Connection Flag (offset 4) | 0x00=cells OK; 0x02=cells disconnected/BMS-lockout indicator |
| 8 | `00` | Reserved (offset 5) | BT-E6001 fault: 0x05 in 1st response, 0x00 later. BT-E6000: always 0x00 |
| 9–10 | `F7 95` | Pack Voltage (offset 6–7) | 0x95F7 = 38391 mV (LE) |
| 11–12 | `04 1E` | Cell V MAX (offset 8–9) | 0x1E04 = 7684 → 3842 mV |
| 13–14 | `FC 1D` | Cell V MIN (offset 10–11) | 0x1DFC = 7676 → 3838 mV |
| 15 | `16` | NTC MAX (offset 12) | 22°C |
| 16 | `15` | NTC AVG (offset 13) | 21°C |
| 17 | `16` | TH002 (offset 14) | 22°C (MOSFET sensor) |
| 18 | `3D` | **SOC** (offset 15) | **61%** |
| 19 | `12` | ChgCtr/MotorConst-lo (offset 16) | Charger: charge counter. Motor: always 0x90 (= register 0xAA byte 0) |
| 20 | `00` | MotorConst-hi (offset 17) | Charger: 0x00. Motor: always 0x01 (= register 0xAA byte 1) |
| 21 | `00` | Current/Load Indicator (offset 18) | Charger: 0x00. Motor: ~0x01 idle, climbs to 0x1C (28) under load |
| 22–24 | `00 00 00` | Reserved (offset 19–21) | Always zero |
| 25–26 | `87 F1` | CRC-16/X-25 | Over bytes 1–24 (LE) |

#### Telemetry Field Map (payload offsets, starting after LENGTH byte)

| Offset | Bytes | Type | Field | Notes |
|--------|-------|------|-------|-------|
| 0 | | uint8 | Cmd | Always 0x10 |
| 1 | | uint8 | **Status / Fault Byte** | 0x00=OK; 0x10=BMS-Lockout; 0x15=Auth-Failed/Degraded; 0x25=No-Cells (per michielvg's cellless scan) |
| 2 | | uint8 | **State** | 0x00=Init, 0x01=Active (motor), 0x02=Precharge, 0x03=Charging |
| 3 | | uint8 | Reserved | Always 0x00 |
| 4 | | uint8 | **Cell Connection Flag** | 0x00=cells OK; 0x02=cells disconnected — appears under BMS-lockout |
| 5 | | uint8 | Reserved | BT-E6001 fault: 0x05 (1st) / 0x00 (later); BT-E6000: always 0x00 |
| 6–7 | LE uint16 | **Pack Voltage (mV)** | See voltage table below |
| 8–9 | LE uint16 | **Cell Voltage MAX (0.5 mV)** | Max cell group voltage. Divide by 2 for mV. Confirmed with multimeter. |
| 10–11 | LE uint16 | **Cell Voltage MIN (0.5 mV)** | Min cell group voltage. Always ~4–8 less than MAX (~2–4 mV). |
| 12 | uint8 | **NTC Temperature MAX (°C)** | MAX of 2x 10K NTC sensors, value is directly °C. See sensor table below. |
| 13 | uint8 | **NTC Temperature AVG (°C)** | AVG of 2x 10K NTC sensors, value is directly °C |
| 14 | uint8 | **TH002 Temperature (°C)** | MOSFET temperature sensor (next to MOSFETs), value is directly °C |
| 15 | uint8 | **SOC (%)** | **Confirmed**: actual state of charge percentage |
| 16 | uint8 | ChgCtr / MotorConst-lo | Charger: charge counter (0–32+, resets per session). Motor: always **0x90** (= register 0xAA byte 0) |
| 17 | uint8 | MotorConst-hi | Charger: 0x00. Motor: always **0x01** (= register 0xAA byte 1) |
| 18 | uint8 | **Current / Load Indicator** | Charger: 0x00. Motor: discharge-current proxy. Calibration (2026-05-09, two-point linear fit on user's BT-E6000): **`I_mA = 43 × byte + 58`**. Datapoints: byte=11 → 531 mA, byte=6 → 316 mA. Offset of 58 mA likely represents BMS+motor electronics quiescent draw. Saturation behavior at higher loads not yet characterized. |
| 19–21 | | | Reserved | Always `00 00 00` |

#### Voltage & SOC observations

**Capture 2026-03-28 ~09:20 UTC** (battery ~61% SOC, ~22°C ambient, charger connected → idle → reconnect → idle → disconnected):

| # | State | Pack Voltage | Cell V MAX | Cell V MIN | NTC MAX | NTC AVG | TH002 | SOC (%) | Charge ctr |
|---|-------|-------------|-----------|-----------|---------|---------|-------|---------|------------|
| 1 | 0x02 | 38246 mV | 3826 mV | 3823 mV | 21°C | 21°C | 20°C | 61% | 0 |
| 2 | 0x03 (Charging) | 38251 mV | 3827 mV | 3824 mV | 21°C | 21°C | 20°C | 61% | 1 |
| 3 (reconnect) | 0x00 (Init) | 38355 mV | 3837 mV | 3834 mV | 21°C | 21°C | 21°C | 61% | 24 |

- Pack voltage: 38.2V → 38.4V (10S = ~3.82–3.84V/cell, consistent with ~61% SOC)
- Cell voltage spread only 3 mV — well balanced pack
- TH002 warmed from 20°C to 21°C during the session
- After reconnect, charge counter carried over from previous session (24), then resets on state transition

**Capture 2026-04-12** (battery ~69% SOC, ~23°C, charger disconnect/reconnect, dual-channel ordered):

| # | State | Pack Voltage | Cell V MAX | Cell V MIN | Spread | NTC MAX | NTC AVG | TH002 | SOC | ChgCtr |
|---|-------|-------------|-----------|-----------|--------|---------|---------|-------|-----|--------|
| 1 | Init | 38845 mV | 3887 mV | 3878 mV | 9 mV | 23°C | 22°C | 24°C | 69% | 4 |
| 2 | Precharge | 38830 mV | 3885 mV | 3881 mV | 4 mV | 23°C | 22°C | 24°C | 69% | 0 |
| 3 | Precharge | 38834 mV | 3885 mV | 3882 mV | 3 mV | 23°C | 22°C | 24°C | 69% | 0 |
| 4 | **Charging** | 38833 mV | 3885 mV | 3882 mV | 3 mV | 23°C | 22°C | 24°C | 69% | 1 |
| 5 | Charging | **38977 mV** | 3900 mV | 3897 mV | 3 mV | 23°C | 22°C | 24°C | 69% | 14 |
| 6 | Charging | 38986 mV | 3900 mV | 3897 mV | 3 mV | 23°C | 22°C | 24°C | 69% | 32 |
| 8 | Charging | 38998 mV | 3903 mV | 3898 mV | 5 mV | 23°C | 22°C | 24°C | 69% | 32 |
| 9 | Charging | 39009 mV | 3903 mV | 3899 mV | 4 mV | 23°C | 22°C | 24°C | 69% | 33 |
| — | *Reconnect* | | | | | | | | | |
| 10 | Init | 38850 mV | 3887 mV | 3884 mV | 3 mV | 24°C | 22°C | 24°C | 69% | 4 |
| 11 | Precharge | 38827 mV | 3885 mV | 3881 mV | 4 mV | 24°C | 22°C | 24°C | 69% | 0 |
| 12 | Charging | 38833 mV | 3885 mV | 3882 mV | 3 mV | 24°C | 22°C | 24°C | 69% | 1 |
| 13 | Charging | 38978 mV | 3900 mV | 3896 mV | 4 mV | 24°C | 22°C | 24°C | 69% | 16 |
| 14 | Charging | 38998 mV | 3902 mV | 3898 mV | 4 mV | 24°C | 22°C | 24°C | 69% | 32 |
| 17 | Charging | 39004 mV | 3904 mV | 3898 mV | 6 mV | 24°C | 22°C | 24°C | 69% | 32 |

- **Voltage jump at Charging start**: 38833 → 38977 mV (+144 mV). This is the IR drop from charge current (~1.8A × ~0.08Ω pack resistance). Visible in both sessions.
- **Every poll receives telemetry** during Charging state — no ack pairs observed.
- **Charge counter**: Init carries over previous session value (4). Resets to 0 at Precharge, increments to 1 at Charging, then jumps non-linearly (14→32→33).
- **NTC MAX warmed** from 23°C to 24°C between sessions (TH002 stayed at 24°C — MOSFET area warm from start).

#### Multi-session capture 2026-03-28 (5x connect/disconnect, battery ~60-70% SOC)

Repeated charger connect/disconnect cycles reveal handshake and SOC reset behavior.

**Handshake sequence across sessions:**

| Session | Initiator | Seq | Handshake |
|---------|-----------|-----|-----------|
| 1 | Charger | 0 | `R2: 00 40 00 21 49` → `R: 00 C0 00 ED C5` |
| 2 | Charger | 1 | `R2: 00 41 00 F9 50` → `R: 00 C1 00 35 DC` |
| 3 | Battery | 0 | `R: 00 C0 00 ED C5` → `R2: 00 40 00 21 49` |
| 4 | Battery | 1 | `R: 00 C1 00 35 DC` → `R2: 00 41 00 F9 50` |
| 5 | Charger | 2 | `R2: 00 42 00 91 7A` → `R: 00 C2 00 5D F6` |

**Telemetry across all sessions:**

| Session | State | Pack Voltage | Cell V MAX | Cell V MIN | Spread | Temps | SOC | Charge ctr |
|---------|-------|-------------|-----------|-----------|--------|-------|-----|------------|
| 1 | 0x00 (Init) | 38241 mV | 3825 mV | 3823 mV | 2 mV | 22/22/22°C | 61% | 0 |
| 1 | 0x02 | 38253 mV | 3827 mV | 3824 mV | 3 mV | 22/22/22°C | 61% | 0 |
| 2 | 0x00 (Init) | 38265 mV | 3828 mV | 3825 mV | 3 mV | 22/22/22°C | 61% | **22** |
| 2 | 0x03 (Charging) | 38260 mV | 3827 mV | 3825 mV | 2 mV | 22/22/22°C | 61% | 1 |
| 3 | 0x00 (Init) | 38278 mV | 3829 mV | 3827 mV | 2 mV | 22/22/22°C | 61% | **4** |
| 3 | 0x03 (Charging) | 38271 mV | 3828 mV | 3826 mV | 2 mV | 22/22/22°C | 61% | 1 |
| 4 | 0x00 (Init) | 38281 mV | 3829 mV | 3827 mV | 2 mV | 22/22/22°C | 61% | **4** |
| 5 | 0x00 (Init) | 38289 mV | 3830 mV | 3828 mV | 2 mV | 22/22/22°C | 61% | **19** |
| 5 | 0x02 | 38278 mV | 3829 mV | 3827 mV | 2 mV | 22/22/22°C | 61% | 0 |

**Key observations from multi-session data:**

- **Charge counter reset behavior**: The first telemetry (State=0x00) carries over the **last charge counter value from the previous session** (22, 4, 4, 19). After the state transitions to 0x02/0x03, the counter resets to 0 or 1 and starts counting up again.
- **Handshake initiator alternates**: Either device can initiate. The handshake sequence number increments independently across sessions, separate from the telemetry sequence counter.
- **Voltage rises continuously**: 38241 → 38289 mV across all 5 sessions, even between disconnects. The battery retains charge between brief disconnect cycles.
- **Cell voltage spread consistently 2–3 mV** — very well balanced pack. Matches multimeter measurement (3834.9–3836.1 mV, spread ~1.2 mV unloaded).
- **NTC AVG temperature increased**: from 21°C to 22°C — battery warming up through repeated charging cycles.

### 5. Idle / Ack Pattern

Between telemetry responses, the battery sends short ack pairs (Length=0, CRC=0x0000):

```
Battery → 00 03 00 00 00       Ping
Battery → 00 00 00 00 00       Ack
```

These appear on CH1 (battery side) and repeat at ~1 second intervals.

## State Transitions

State byte values (telemetry offset 2):

| State | Name | Context | Notes |
|-------|------|---------|-------|
| 0x00 | Init | Both | Initial state after handshake / first telemetry |
| 0x01 | Active | Motor mode | Set after motor's first ready poll (`03 31 00 00`); MOSFETs open for discharge to motor |
| 0x02 | Precharge | Charger mode | Brief transition state; charger detected, BMS gating in current |
| 0x03 | Charging | Charger mode | Steady-state charge; MOSFETs open for charge from charger |

Charger mode flow: `Init → Precharge → Charging` (steady polls keep state=Charging).
Motor mode flow: `Init → Active` (single transition on first ready-poll, stays Active until shutdown).

## Charge Current Measurement

Measured externally via the battery's shunt resistors: 2x 1mΩ (SMD marking "1L00") in parallel, in series with GND → **R_shunt = 0.5 mΩ**.

| Phase | U_shunt | Calculated I | Multimeter I |
|-------|---------|-------------|-------------|
| State 0x00 (Init) | 0–0.02 mV | ~0 A | — |
| State 0x02 (Precharge) | 0.91 mV | 1.82 A | ~1.7 A |
| Charging steady (~30s) | 0.95 mV | 1.9 A | — |

**Charge current is NOT reported in the Cmd 0x10 telemetry.** No field correlates with the measured 1.7–1.9 A. This makes sense: the charger is a "dumb" power supply, and all charging logic resides in the battery BMS — it has no need to report the current back to the charger.

## Temperature Sensors

The battery contains 3 temperature sensors. Each NTC is connected to a separate GPIO on the battery's microcontroller. Values at offsets 11–13 are **directly in °C** — no scaling needed.

Sensor designators vary by battery model:

| | NTC pair (cells) | MOSFET sensor |
|---|---|---|
| **BT-E6000** | TH003, TH004 | TH002 |
| **BT-E6001** | TH001, TH002 | TH003 |

| Offset | Field | Description |
|--------|-------|-------------|
| 11 | NTC MAX | Maximum of TH003/TH004 (cell temperature NTCs) |
| 12 | NTC AVG | Average of TH003/TH004 (cell temperature NTCs) |
| 13 | TH002 | MOSFET temperature sensor, mounted next to the MOSFETs |

### Temperature observations across sessions

| Date / Capture | NTC MAX | NTC AVG | TH002 | SOC (Byte 14) |
|----------------|---------|---------|-------|---------------|
| 2026-03-28 session start (61% SOC, cold) | 0x15 (21°C) | 0x15 (21°C) | 0x14 (20°C) | 0x3D (61%) |
| 2026-03-28 after charging (cold) | 0x15 (21°C) | 0x15 (21°C) | 0x15 (21°C) | 0x3D (61%) |
| 2026-03-28 5x reconnect (cold) | 0x16 (22°C) | 0x16 (22°C) | 0x16 (22°C) | 0x3D (61%) |
| 2026-03-28 heat test 1 (warm start) | 0x16 (22°C) | 0x15 (21°C) | 0x16 (22°C) | 0x3D (61%) |
| **2026-03-28 heat test 2 (pre-warmed)** | **0x27 (39°C)** | **0x1E (30°C)** | **0x2B (43°C)** | **0x3E (62%)** |
| heat test 2 — cooling | 0x25 (37°C) | 0x1C (28°C) | 0x2A (42°C) | 0x3E (62%) |
| heat test 2 — further cooling | 0x24 (36°C) | 0x1B (27°C) | 0x29 (41°C) | 0x3E (62%) |

- **TH002 is the hottest sensor** — 43°C vs NTC MAX 39°C. TH002 sits next to the MOSFETs, which conduct heat faster than the cell pack.
- **NTC AVG lags significantly behind NTC MAX**: 30°C vs 39°C — confirms one NTC sensor heats faster than the other (asymmetric placement).
- Temperatures **cool down across sessions** as the hair dryer was removed: 39→37→36 (MAX), 43→42→41 (TH002).
- At room temperature (~22°C), all three sensors read within 1-2°C of each other.

## Sequence Number Rotation

Both charger and battery use a rotating sequence number (0→1→2→3→0→...) in the lower nibble of the header byte. This is used across all message types.

## Motor/Display ↔ Battery Communication

Captured 2026-03-29 with BT-E6000 in bike frame, communicating with motor (DU-E6012) and display (SC-E6010). Same bus, same addresses, but different poll payload and additional commands.

### Differences from Charger

| Feature | Charger (EC-E6002) | Motor/Display (DU-E6012) |
|---------|-------------------|---------------|
| Handshake sender | `00 4X` seq=any | `00 40` seq=0 (typically) |
| Poll payload bytes 1–2 | Always `00 00` | `02 02` (boot), `03 31` (first ready), `03 05` (steady) |
| Telemetry State (offset 2) | 0x00/0x02/0x03 (Init→Pre→Chg) | 0x00 (Init) → 0x01 (Active) |
| Telemetry offset 16–17 | Charge counter (0–32) / 0x00 | `90 01` (constant, = register 0xAA) |
| Telemetry offset 18 | Always 0x00 | 0x01 idle, up to 0x1C under load |
| Auth flavor | `02 01 ...` (cmd 0x30 payload[1..2]) | `03 02 00 00 ...` |
| Startup commands | 0x30 (auth), 0x31 (specs) | 0x30 (auth), 0x11 (DevInfo), 0x32 (Trip) |
| Shutdown command | — | 0x21 (sent on display power-off) |
| Telemetry rate | Every poll | Every poll |
| Frame burst pattern | Frames glued in 2 bursts (HS+Auth, then Specs+Polls) | Each frame as separate UART transmission |

### Startup Sequence (Motor/Display)

Motor sends each frame as a separate UART transmission (not bursted). Battery typically initiates with its own Ping; motor responds with Pong then proceeds.

```
1. Battery → 00 C0 00 ED C5                                                          (battery Ping, seq=0)
2. Motor   → 00 40 00 21 49                                                          (motor Pong, seq=0)
3. Motor   → 00 01 11 30 03 02 00 00 X0 X1 X2 X3 Y0 Y1 X0 X1 X2 X3 Z0 Z1 CRC1 CRC2  (Auth-Req, motor flavor)
4. Battery → 00 81 12 30 00 [16 bytes cryptographic response] CRC1 CRC2              (Auth-Resp)
5. Battery → 00 82 16 10 00 00 00 00 00 ... CRC1 CRC2                                (first Status, State=Init)
6. Motor   → 00 02 05 10 02 02 00 00 C2 97                                           (Boot Poll, payload 02 02 00 00)
7. Battery → 00 83 09 11 00 2A 00 CE 01 00 00 5D CRC1 CRC2                           (DevInfo-Resp)
8. Motor   → 00 03 01 11 78 31                                                       (DevInfo-Req — sometimes appears AFTER battery's resp)
9. Battery → 00 80 16 10 00 01 00 00 00 ... 90 01 03 ... CRC1 CRC2                   (Status with State=01 Active)
10. Motor  → 00 00 05 10 03 31 00 00 08 D5                                           (first Ready Poll, payload 03 31 00 00)
11. Battery→ 00 81 02 32 00 A1 FD                                                    (Battery sends Trip request, 2-byte payload)
12. Motor  → 00 01 07 32 1A 05 06 11 3A 36 BB 47                                     (Trip-Req, 6-byte payload)
13. Motor  → 00 02 05 10 03 05 00 00 7C 07                                           (Steady Ready Poll, payload 03 05 00 00)
... continues with poll/response cycle every ~1 second ...
```

**Order observation**: the motor sometimes interleaves frames (e.g., DevInfo-Req arrives after battery already sent DevInfo-Resp). The battery responds independently to each request as it processes them. The protocol is event-driven, not strict request-response.

### Motor Simulation Without Real Bike (verified 2026-05-09)

A standalone microcontroller (ESP32 with TinyC firmware) can fully impersonate the motor and bring the BMS into Active state — releasing the discharge MOSFETs — without any real bike, motor, or charger present. The complete recipe:

1. **Hardware**: connect ESP32 GPIO19 ↔ Battery TX, GPIO18 ↔ Battery RX, GND ↔ Battery GND. The "wake" mechanism is automatic: when the ESP32 configures GPIO18 as UART TX, the line idles at 3.3V which triggers the BMS wake-latch (Q024/Q002) and powers up the BMS MCU.

2. **Cold-wake bursts**: 3× raw `00 40 00 21 49` at T+280, T+480, T+680 ms — bootstraps the BMS MCU if it was sleeping. Battery responds with its own `00 C0 00 ED C5` Ping when ready.

3. **Wake sequence** (each frame as a separate UART transmission, with ~1-3 ms gaps between bytes):
   - HS-Pong `00 40 00 21 49`
   - Auth-Req with **replayed bytes from a real motor session** (random structurally-correct bytes are rejected — see Cmd 0x30 section)
   - Boot Poll `02 02 00 00`
   - DevInfo-Req
   - First Ready Poll `03 31 00 00`
   - Trip-Req with 6-byte payload (e.g., `1A 05 06 11 3A 36`)

4. **Steady polling**: `03 05 00 00` every ~1 second indefinitely. Battery returns full Status with `State=01 (Active)`, `Fault=0x00`, real Vbat/cell/temp/SOC and motor current indicator at offset 18.

5. **Shutdown**: send `cmd 0x21` (Shutdown), wait ~200 ms for ack, then drive GPIO18 to GND (release UART, set as OUTPUT LOW). The BMS wake-latch deactivates, MCU goes to sleep, MOSFETs close.

**Critical implementation details:**
- **Inter-byte timing on TX is non-negotiable** (`delayMicroseconds(2500)` between `serialWriteByte` calls). Burst-sending via `serialWriteBytes(buf, len)` is silently rejected — no Auth-Resp, fault byte flips to 0x15 after ~8s.
- **Auth-Req must be a replay of bytes the battery has previously seen from a real motor session.** Random bytes with the correct X/Y/X/Z structure don't pass.
- The transition `State=Init → Active` requires the full sequence including Trip-Req — sending only HS+Auth+BootPoll+DevInfo and then steady polls keeps the battery in Init forever and eventually flips to fault state.

This procedure was originally demonstrated by [gregyedlik/BT-E60xx](https://github.com/gregyedlik/BT-E60xx) on a Raspberry Pi using `pyserial` with byte-by-byte transmission timing. We independently verified the same approach on ESP32 after diagnosing why a naive batch-write port failed (the inter-byte timing requirement).

### Charger Simulation Without Real Charger (verified 2026-05-09)

A separate ESP32 mode can impersonate the **charger** instead of the motor, bringing the BMS into Charging state and releasing the MOSFETs to accept current from any external CC/CV power supply (no real Shimano EC-E6002 charger needed). Verified on BT-E6000 with a 41.5 V bench supply: state went `Init → Pre → Chg`, Vbat climbed visibly through the IR-drop path, ChgCtr (offset 16) incremented.

**Recipe:**

1. **Hardware**: ESP32 wired as in motor simulation (GPIO18→B-RX, GPIO19→B-TX, GND→GND), plus external CC/CV power supply (set 41.5 V, 1-2 A current limit) wired to the battery's main + and − contacts.

2. **Auth-Req payload**: capture the real charger's Auth-Req bytes by sniffing a single live charger session on the same battery. Bytes from a different battery (or the same battery from a much older session) are rejected. The Auth-Req must be sent as the second of two **separate UART transmissions** with an ~80 ms gap after the HS-Pong:
   - Frame 1: HS-Pong `00 41 00 F9 50` (5 bytes, sender 0x40 + seq=1)
   - **Wait 80 ms**
   - Frame 2: Auth-Req `00 02 11 30 02 01 [16 captured payload bytes] CRC1 CRC2` (22 bytes, sender 0x00 + seq=2)
   
   Sending HS+Auth as a single 27-byte burst — even with correct inter-byte timing — gets the Auth-Req silently ignored (battery only ACKs the HS as `00 C1 00 35 DC`). The BMS uses inter-frame gap as a structural validator beyond per-byte timing.

3. **Specs-Req (static, identical across sessions)**: `00 03 0B 31 9E 01 A5 01 01 00 05 00 10 00 A9 BC` — battery responds with the 18-byte Specs-Resp.

4. **Steady polling**: `00 SEQ 05 10 00 00 00 00 CRC` every ~1 s. Once the external voltage is detected, state advances `0x00 (Init) → 0x02 (Pre) → 0x03 (Chg)` within 1-2 polls. ChgCtr in offset 16 increments non-linearly (typically 0 → ~16 → ~32 within a few polls).

**Critical implementation details (in addition to motor-mode requirements):**
- **HS-Pong and Auth-Req must be separate UART transmissions** with ~80 ms inter-frame gap — combined-burst sending silently fails Auth even with valid bytes.
- **Charger Auth-Req is per-battery**, not universal. Each battery requires its own captured Auth-Req bytes (likely a per-battery key or per-session nonce). Static replay across batteries fails.
- External voltage at the charger contacts must exceed Vbat by enough to drive current — empirically a 41.5 V supply against a ~37 V pack is sufficient. With supply at or below Vbat the BMS sees no charge source and won't transition state.

### Shutdown Sequence

```
Motor  → 00 00 01 21 9F EF            Cmd 0x21, Length=1 (shutdown request)
Battery→ 00 80 03 21 00 00 08 39      Cmd 0x21, Length=3 (shutdown ack, payload: 21 00 00)
```

### New Command Types

#### Cmd 0x11 — Device Info (Length=1 request, Length=9 response)

Motor requests battery info. Battery responds with 9-byte payload:
```
R2: 00 00 01 11 1C DE                           Motor request
R:  00 80 09 11 00 29 00 C3 01 00 00 5D 72 8B   Battery response
                 ^^                               0x29=41 — capacity? model?
                       ^^ ^^                      0xC3 0x01 — firmware?
                                   ^^             0x5D=93
```
This exchange happens once at startup, after the initial boot poll.

#### Cmd 0x32 — Trip/Config (variable length)

Bidirectional exchange, appears during normal motor operation:
```
R:  00 81 02 32 00 A1 FD                        Battery→Motor (2-byte payload: 32 00 = trip request from battery)
R2: 00 02 07 32 1A 03 1D 0F 17 18 29 67         Motor→Battery (7-byte payload: 32 + 6 data bytes)
R:  00 82 02 32 00 6C D8                        Battery→Motor (Trip-Resp / ack)
```

The 6-byte motor data payload (after cmd 0x32 echo) varies between sessions:
- Session A: `1A 03 1D 0F 17 18`
- Session B: `1A 05 06 11 3A 36`
- Session C: `1A 05 07 12 36 17`

First byte (`0x1A` = 26) is constant across all observed sessions — possibly day-of-month or a frame-type marker. Remaining 5 bytes change. Hypothesis: timestamp (date+time) but exact field layout unconfirmed.

#### Cmd 0x21 — Shutdown (Length=1 request, Length=3 response)

Sent by motor/display when user presses power button on display:
```
R2: 00 00 01 21 9F EF          Shutdown request
R:  00 80 03 21 00 00 08 39    Shutdown acknowledgment
```

### Driving Telemetry

During slow ECO mode riding, voltage drops and offset 17 increases:

| Condition | Pack Voltage | Cell V MAX | Cell V MIN | Spread | Offset 18 |
|-----------|-------------|-----------|-----------|--------|-----------|
| Idle (motor on) | 38320 mV | 3834 mV | 3830 mV | 4 mV | 0x01 |
| Driving (ECO) | 38182 mV | 3820 mV | 3815 mV | 5 mV | 0x1C (28) |
| After stop | 38295 mV | 3831 mV | 3828 mV | 3 mV | 0x01 |

- Voltage drop of **~140 mV** under load
- Cell spread increases from 4 mV to 5 mV under load
- **Offset 18 jumps to 0x1C (28) during riding** — possibly discharge current indicator
- Temperatures stable at 14°C / 14°C / 13–14°C (outdoor, cooler day)
- SOC = 0x3D (61%) throughout

## BT-E6001 Fault Analysis — Battery Reports 0V, Charging Fails

Captured 2026-04-03 with a defective BT-E6001 battery connected to EC-E6002 charger. The battery communicates on the UART bus but reports zero pack voltage — charger cannot initiate charging.

[Full log](logs/2026-04-03_bt-e6001_charger_fault.log)

### Communication Anomalies

| Observation | BT-E6000 (healthy) | BT-E6001 (defective) |
|-------------|--------------------|-----------------------|
| Handshake response | Immediate | 3 retries before response |
| Charger poll byte 1 | Always `00` | `04` initially, then `00` after handshake |
| Status / Fault Byte (offset 1) | 0x00 (OK) | **0x10 (BMS-Lockout)** in first response |
| Cell Connection Flag (offset 4) | 0x00 (OK) | **0x02 (No-Cell-Conn)** |
| Reserved offset 5 | 0x00 | 0x05 (1st response) / 0x00 (later) |
| Pack voltage (offset 6–7) | 38200–38400 mV | **0 mV** |
| Cell V MAX/MIN (offset 8–11) | 3820–3840 mV | **0 mV** |
| NTC MAX / AVG / TH003 (offset 12–14) | 20–39°C | 25°C / 25°C / 25°C (all normal) |
| SOC (offset 15) | 61–62% | 29% (likely EEPROM-cached) |
| Reaches State 0x03 | Yes (Charging) | **No** — stuck at 0x02 (Precharge) |

### Telemetry Decode

```
BT-E6001 (defective):
   00 82 16 10 10 00 00 02 05 00 00 00 00 00 00 19 19 19 1D 00 00 00 00 00 00 96 1C  ← 1st response (charger poll with 0x04 flag)
   00 82 16 10 00 02 00 02 00 00 00 00 00 00 00 19 19 19 1D 00 00 01 00 00 00 50 88  ← 2nd response (after handshake, normal poll)

BT-E6000 (healthy, for comparison):
   00 83 16 10 00 00 00 00 00 B1 95 F4 1D EC 1D 1C 1A 1B 3E 00 00 00 00 00 00 1D 8D  ← Init (State=0x00)
   00 81 16 10 00 02 00 00 00 BA 95 F4 1D F0 1D 1C 1A 1B 3E 01 00 00 00 00 00 A4 59  ← Precharge (State=0x02)

         ^^ ^^    ^^          ^^^^^ ^^^^^ ^^^^^ ^^ ^^ ^^ ^^
         LL Cmd   State       PackV  MaxV  MinV Mx Av T2 SOC
```

| Field | BT-E6001 (defective) | BT-E6000 (healthy) |
|-------|----------------------|--------------------|
| Status / Fault Byte (offset 1) | **0x10 (BMS-Lockout)** (1st) / 0x00 (2nd) | 0x00 (always) |
| State (offset 2) | 0x00 → 0x02 | 0x00 → 0x02 |
| Cell Connection (offset 4) | **0x02 (No-Cell-Conn)** | 0x00 (always) |
| Reserved (offset 5) | 0x05 / 0x00 | 0x00 (always) |
| PackV (offset 6–7) | **0 mV** | 38321 mV / 38330 mV |
| MaxV (offset 8–9) | **0** | 3834 mV / 3834 mV |
| MinV (offset 10–11) | **0** | 3830 mV / 3832 mV |
| NTC MAX (offset 12) | 25°C | 28°C |
| NTC AVG (offset 13) | 25°C | 26°C |
| TH002/TH003 (offset 14) | 25°C | 27°C |
| SOC (offset 15) | 29% (EEPROM) | 62% |
| ChgCtr (offset 16) | 0 / 0 | 0 / 1 |

### Diagnosis

1. **Pack voltage = 0 mV**: The BMS has disconnected the cells from the output (MOSFET protection active). The voltage measurement point is after the FETs.
2. **Temperature sensors all normal** (25°C at room temperature) — no sensor fault.
3. **Status / Fault Byte (offset 1) = 0x10**: BMS-Lockout flag. Only seen in first telemetry, clears to 0x00 in subsequent responses.
4. **Cell Connection Flag (offset 4) = 0x02**: cells reported as disconnected — confirmed indicator of BMS lockout state. Never seen with BT-E6000 healthy. Independently confirmed by michielvg's cellless PCB scan (same 0x02 in cmd 0x10 response without cells physically connected).
5. **Offset 5 = `05` then `00`**: secondary status byte that changes over the session. Possibly a sub-state or retry counter related to the lockout state.
6. **SOC = 29%**: Likely an EEPROM-stored value from before the fault occurred. Without cell voltage measurement, the BMS cannot calculate live SOC.
7. **Charger poll byte 1 = 0x04**: The charger sends 0x04 when the handshake failed (3 retries without response). After successful handshake, reverts to 0x00. Possible meaning: error recovery / retry mode.

The combination of fault byte 0x10 + cell-conn flag 0x02 + Vbat=0 is a consistent fingerprint for "BMS has latched cells out of the output path" — same pattern observed both with the defective BT-E6001 and with michielvg's cellless PCB scan.

### Possible Root Causes

- **BMS lockout**: Over-discharge, over-current, or short-circuit protection triggered. FETs remain off.
- **Cell imbalance or deep discharge**: If cells are below safe voltage threshold (<2.5V), the BMS blocks output. SOC 29% would be plausible for a battery that sat discharged for a long time.

**Recommended next step**: Measure cell voltages directly at the balance connector to determine if cells are alive or deeply discharged.

## Command Register Scan

Full command scan performed by [michielvg](https://github.com/michielvg/Shimano_BT-E6000_BMS/discussions/3#discussioncomment-16463975) on a BT-E6000 BMS PCB **without cells connected**. Each command was sent as a 2-byte request (`cmd 00`) instead of the charger's usual 5-byte format — the BMS responds to both.

Commands that return `<cmd> 01` = "command unknown" (not listed). Timeouts also indicate possible valid commands (0x31 is known but timed out).

### Responding Commands

| Cmd | Resp Len | Response Payload (after cmd echo) | Notes |
|-----|----------|-----------------------------------|-------|
| 0x10 | 22 | `25 00 00 02 00 E5 00 66 00 08 00 ...` | Telemetry (known). Status=0x25 (no cells), offset 4=0x02 |
| 0x11 | 9 | `25 47 00 0F 03 00 00 64` | Device info (known). Byte 1=0x25 |
| 0x12 | 10 | `25 00 E1 00 00 90 10 0F 00` | **NEW** — unknown |
| 0x13 | 32 | `25 00 01 01 00 04 0A 01 02 52 0A ...` | **NEW** — large config/calibration block? |
| 0x20 | 3 | `25 00` | **NEW** — unknown |
| 0x21 | 3 | `25 FF` | Shutdown (known). Byte 2=0xFF (vs 0x00 with cells) |
| 0x30 | 2 | `12` | **NEW** — byte 1=0x12, different status format |
| 0x31 | — | — | **TIMEOUT** (known from motor, no response here) |
| 0x32 | 2 | `12` | Trip/Config (known). Byte 1=0x12 |
| 0xA0 | 43 | `00 00 00 00 21 00 0E 00 33 00 32 ...` | **NEW** — largest response, diagnostics? |
| 0xA6 | 7 | `A1 17 60 56 52 4B` | **NEW** — contains ASCII "VRK" |
| 0xA7 | 7 | `CC 00 F3 55 52 4B` | **NEW** — contains ASCII "URK" |
| 0xAA | 3 | `90 01` | **NEW** — matches motor telemetry offset 16–17! |
| 0xAB | 3 | `06 01` | **NEW** — unknown |
| 0xBB | 4 | `00 00 00` | **NEW** — unknown |
| 0xCB | 3 | `00 00` | **NEW** — unknown |

### Timeout Commands (possible valid, no response)

0xA1–0xA5, 0xA8–0xA9, 0xAC–0xAF, 0xB0–0xBA, 0xBC–0xBF, 0xCC–0xCF

### Key Observations

**Status byte (byte 1 after cmd echo):**

| Value | Meaning | Seen in |
|-------|---------|---------|
| 0x00 | OK / normal | BT-E6000 healthy (our captures), 0xA0+ commands |
| 0x10 | BMS-Lockout (cells disconnected, FETs off) | BT-E6001 defective; combined with cell-conn flag 0x02 at offset 4 |
| 0x12 | ? | 0x30, 0x32 commands (older capture) |
| 0x15 | Auth-Failed / Degraded mode | Simulator boot without valid Auth-Req replay; battery still answers but refuses Active state |
| 0x25 | No cells connected | michielvg's PCB scan (0x10–0x21) |

**Offset 4 = 0x02 confirmed as "no cell connection":** michielvg's cellless PCB shows the same `0x02` at offset 4 in 0x10 telemetry as our defective BT-E6001. This is a hardware fault indicator, not a protocol version difference.

**Cmd 0xAA = Register behind motor telemetry offset 16–17:** The response `90 01` is identical to the constant value at telemetry offset 16–17 in motor mode. The motor/display likely reads this register and the BMS embeds it in the telemetry stream.

**Minimal request format works:** The charger sends 5-byte polls (`10 00 00 00 00`), but 2-byte requests (`cmd 00`) also get full responses. The extra bytes in the charger poll are optional padding.

**ASCII in 0xA6/0xA7:** Bytes `56 52 4B` ("VRK") and `55 52 4B` ("URK") could be fragments of a serial number or model identifier.

## Open Questions

- **Cmd 0x30 authentication algorithm**: What crypto algorithm generates the X/Y/Z fields in motor Auth-Req and the 16-byte Auth-Resp? Static replay of known-working bytes is sufficient for full motor simulation, but generating fresh valid bytes (instead of replaying captured ones) requires understanding the algorithm. Either (a) a small key-derived set of blessed challenges is stored in the BMS, or (b) the motor MCU computes a MAC the battery verifies. Without firmware reverse engineering the algorithm remains unknown. The motor does not validate the response, so authentication appears one-way (battery validates motor).
- **Cmd 0x31 specifications**: What are offsets 10–17 in the response? Max current, voltage limits, cycle count?
- **Cmd 0x31 value 414/415 vs 421/425**: Remaining vs design capacity in Wh? How are the charger's request values derived?
- **Cmd 0x11 payload**: What do the 9 response bytes represent? Battery model, capacity, firmware version?
- **Cmd 0x12**: Appears in some motor startup sequences (e.g., gregyedlik recording). Purpose unknown.
- **Cmd 0x13** (32 bytes): Large response — calibration data? Cell configuration?
- **Cmd 0x20** (3 bytes): New command, purpose unknown
- **Cmd 0xA0** (43 bytes): Largest response — extended diagnostics? Individual cell data?
- **Cmd 0xA6/0xA7** (7 bytes each): Contain ASCII fragments ("VRK", "URK") — serial number?
- **Cmd 0x32 payload format**: First byte is consistently 0x1A across sessions; remaining 5 bytes change. Date/time? Odometer fragments? Trip metadata?
- **Status / Fault Byte values**: 0x00 / 0x10 / 0x15 / 0x25 confirmed. Is this a bitfield (each bit = a fault category) or an enumeration? Bit 0x05 appears in 0x15 but not 0x10 — suggests bitfield.
- **Poll payload bytes 1–2 mode bytes**: Motor sends `02 02` (boot), `03 31` (first ready), `03 05` (steady), `03 03` (gregyedlik early), `03 01` (gregyedlik late). The second byte may encode assist level or system substate but mapping not confirmed.
- **Charge counter non-linear**: Jumps from 1→14→32 in ~3 polls. Not a simple per-poll increment. What triggers the jumps?


## Logs

### 2026-04-12 — Charger dual-channel capture with disconnect/reconnect (69% SOC, ~23°C)

First clean dual-channel capture with chronological ordering. Reveals Cmd 0x30 (authentication) and Cmd 0x31 (battery specs) during charger startup. Charger disconnected and reconnected mid-capture.

[Full log](logs/2026-04-12_charger_dual_channel.log)

### 2026-03-28 ~09:20 UTC — Charger session with reconnect (61% SOC, ~22°C)

Battery at 61% SOC (2 LEDs solid, 3rd blinking). Charger connected, ran for ~2 minutes idle polling, disconnected and reconnected once, then disconnected.

[Full log](logs/2026-03-28_0920_charger_reconnect.log)

### 2026-03-28 ~08:50 UTC — 5x connect/disconnect (~61% SOC)

Battery ~60-70% SOC, 2 LEDs solid + 3rd blinking. EC-E6002 charger connected and disconnected 5 times rapidly.

[Full log](logs/2026-03-28_0850_5x_connect_disconnect.log)

### 2026-03-28 — Heat test with hair dryer (~61% SOC, starting ~22°C)

Battery slowly heated with a hair dryer while charger connected. Starting temperature ~22°C.

[Full log](logs/2026-03-28_heat_test.log)

#### Telemetry during heat test

| # | State | Pack Voltage | Cell V MAX | Cell V MIN | NTC MAX | NTC AVG | TH002 | SOC | Charge ctr |
|---|-------|-------------|-----------|-----------|---------|---------|-------|-----|------------|
| 1 | 0x00 (Init) | 38276 mV | 3829 mV | 3826 mV | 22°C | 21°C | 22°C | 61% | 0 |
| 2 | 0x03 (Charging) | 38456 mV | 3847 mV | 3844 mV | 22°C | 21°C | 22°C | 61% | 32 |

**Observations:**
- Voltage jump of **180 mV** (38276 → 38456 mV) between first and second telemetry — larger than previous sessions
- Cell voltages rose by 18 mV (3829→3847 / 3826→3844) — consistent with pack voltage increase
- NTC MAX stayed at 22°C, NTC AVG at 21°C, TH002 at 22°C — temperature sensors have not yet reflected the external heating (likely slow thermal conduction to sensor location)
- SOC remains 61%, unaffected by heating
- Charge counter jumped from 0 to 32 in the second telemetry — much higher than in previous sessions (which typically showed 0→1)

### 2026-03-28 — Heat test pre-warmed (62% SOC, starting ~39°C)

Battery pre-warmed with hair dryer for several minutes before connecting charger. Charger connected and disconnected multiple times while battery cooled.

[Full log](logs/2026-03-28_heat_test_prewarmed.log)

#### Telemetry during pre-warmed heat test

| Session | State | Pack Voltage | Cell V MAX | Cell V MIN | NTC MAX | NTC AVG | TH002 | SOC | Charge ctr |
|---------|-------|-------------|-----------|-----------|---------|---------|-------|-----|------------|
| 1 | 0x00 (Init) | 38296 mV | 3831 mV | 3829 mV | **39°C** | **30°C** | **43°C** | **62%** | 0 |
| 2 | 0x00 (Init) | 38327 mV | 3834 mV | 3831 mV | 37°C | 28°C | 42°C | 62% | 22 |
| 3 | 0x00 (Init) | 38330 mV | 3834 mV | 3832 mV | 37°C | 28°C | 42°C | 62% | 14 |
| 4 | 0x00 (Init) | 38341 mV | 3836 mV | 3833 mV | 36°C | 27°C | 41°C | 62% | 23 |
| 4 | 0x02 (Precharge) | 38336 mV | 3835 mV | 3833 mV | 36°C | 27°C | 41°C | 62% | 0 |

**Key findings:**

- **SOC confirmed: Byte 14 = actual SOC percentage.** Changed from 0x3D (61%) in all previous cold captures to **0x3E (62%)** — the battery charged by 1% during the earlier sessions.
- **Temperature sensors clearly respond to heating**: NTC MAX 39°C, NTC AVG 30°C, TH002 43°C (vs ~22°C at room temperature)
- **TH002 is the hottest sensor** — consistently 4-6°C above NTC MAX. Located next to the MOSFETs, which conduct heat faster.
- **NTC AVG confirms asymmetric NTC placement**: 30°C vs MAX 39°C means one NTC sensor reached ~39°C while the other was much cooler (~21°C), averaging to 30°C.
- **Battery cooling visible** across sessions: TH002 43→42→42→41°C, NTC MAX 39→37→37→36°C, NTC AVG 30→28→28→27°C
- **Cell voltages increase with temperature**: ~3831/3829 mV at 39°C vs ~3825/3823 mV at 22°C. Consistent with Li-Ion OCV temperature coefficient.

### 2026-03-28 — Charge current measurement (62% SOC, ~28°C)

Shunt voltage measured across 2x 1mΩ parallel resistors (R_shunt = 0.5 mΩ) in series with GND. Simultaneously with multimeter on charger cable.

[Full log](logs/2026-03-28_current_measurement.log)

#### Telemetry vs measured current

| Telemetry | State | U_shunt | I_calc | I_multimeter | Cell V MAX | Cell V MIN |
|-----------|-------|---------|--------|-------------|-----------|-----------|
| 1 | 0x00 (Init) | 0–0.02 mV | ~0 A | — | 3834 mV | 3830 mV |
| 2 | 0x02 (Precharge) | 0.91 mV | 1.82 A | ~1.7 A | 3834 mV | 3832 mV |

**Conclusion:** Offsets 7–10 do not represent charge current. Cell voltages remain nearly constant (3834 mV) despite current changing from 0 to 1.82 A — consistent with cell voltage interpretation.

#### Cell voltage verification

Multimeter measurement of all 10 cell groups (charger disconnected, 62% SOC):
- Range: **3834.9 – 3836.1 mV** (spread 1.2 mV)
- Telemetry Cell V MAX/MIN at same SOC: 3834/3830 mV (under load)
- Values match within measurement tolerance, confirming offsets 7–10 as cell group voltages in 0.5 mV units.

### 2026-03-29 — Bike power on/off, test 1 (61% SOC, ~14°C)

Battery in bike frame. Powered on via display, idle for ~30 seconds, powered off via display button.

[Full log](logs/2026-03-29_test_with_bike_on_1.log)

Shows full startup sequence (handshake → Cmd 0x11 → Cmd 0x32 → steady polling) and shutdown (Cmd 0x21).
Telemetry State = 0x01 (Active), temperatures 14°C (outdoor). New commands 0x11, 0x32, 0x21 first observed here.

### 2026-03-29 — Bike driving ECO mode, test 2 (61% SOC, ~14°C)

Battery powered on, slow riding in ECO assist mode, then powered off.

[Full log](logs/2026-03-29_test_with_bike_driving_2.log)

Voltage drop visible during riding: 38320 mV (idle) → 38182 mV (under load). Offset 18 increases from 0x01 to 0x1C (28) during motor assist. TH002 dropped from 14°C to 13°C (outdoor cooling). One garbled message visible (bus contention during driving).

### 2026-03-29 — Bike power on/off, test 3 (61% SOC, ~14°C)

Short on/off cycle, same as test 1. Multiple handshake retries visible at startup.

[Full log](logs/2026-03-29_test_with_bike_on_3.log)

### 2026-04-03 — BT-E6001 charger fault (29% SOC cached, ~25°C)

Defective BT-E6001 battery. Charger connects but battery reports 0V pack voltage. Charging never starts (stuck at Precharge). See [BT-E6001 Fault Analysis](#bt-e6001-fault-analysis--battery-reports-0v-charging-fails) for full decode.

[Full log](logs/2026-04-03_bt-e6001_charger_fault.log)

### 2026-05-09 — BT-E6000 + real Shimano charger live capture (51% SOC, ~22°C)

Sniffer-mode capture of the actual EC-E6002 charger connecting to the user's BT-E6000. Shows the full charger startup sequence with **fresh** Auth-Req bytes that this specific battery accepts. The Auth-Req payload `02 01 86 BB D2 62 AF 75 42 0E 82 4B 93 F0 3C 06` triggered a valid 18-byte Auth-Resp from the battery. State transitions are visible: Init (frame 491) → Pre (494) → Chg (497+) with charge counter incrementing 0 → 02 → 1D → 20 → 21. Used as the reference Auth-Req payload for the ESP32 simulator's Sim-Charger mode.

[Full log](logs/2026-05-09_bt-e6000_charger.log)

### 2026-05-07 — Bike on/off cycles + ECO ride + assist mode toggling (52% SOC, ~22°C)

BT-E6000 in bike. Multiple display power on/off cycles, brief ECO-mode ride, manual assist mode toggling on the display (OFF / ECO / MAX). First capture with the new ESP32 logger using length-based frame parsing — every motor frame appears as a separate UART transmission, revealing that motor frames are NOT bursted (an artifact of the older gap-based parser).

Key findings from this capture:
- Motor sends each frame as a discrete UART transmission with brief inter-frame gaps
- Auth-Req payload follows structure `[03 02 00 00] [X4][Y2][X4][Z2]` with X-block repeating
- Two distinct Auth-Req captures with different X/Y/Z values from the same battery (one per session)
- First ready poll uses `03 31 00 00`, then transitions to `03 05 00 00` for steady state
- Trip-Req payload starts with `0x1A` consistently across sessions

[Full log](logs/2026-05-07_test_with_bike_onoff.log)
