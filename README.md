# Shimano-Steps-Simulator-BT-E6000
Shimano Steps Simulator for simulating an original battery on an e-bike (DIY) or for charging an original battery (without the original charger) or for releasing the voltage (e-bike motor simulation). Running on ESP32 with Tasmota TinyC.

## ESP32 TinyC Program — `Tasmota-TinyC/ShimanoSniffer.tc`
<img width="300" height="600" alt="image" src="https://github.com/user-attachments/assets/54052b46-3a37-4dec-b321-ce6dc8b0748c" />

The Simulator code runs on an ESP32 with [Tasmota TinyC](https://github.com/gemu2015/Sonoff-Tasmota/tree/universal/tasmota/tinyc) for standalone, network-connected operation (no Pi needed). The Shimano protocol decoder, plus three operating modes selectable from a Tasmota web UI:

| Mode | Behavior |
|------|----------|
| **Sniffer** | Passive dual-channel capture on GPIO18 (charger/motor TX) and GPIO19 (battery TX). Logs decoded frames live, optionally to flash file `/shimano.log`. |
| **Simulator** | ESP32 acts as motor or charger. `[Sim-Motor]` runs the full motor wake (cold-wake handshake bursts → Auth replay → Boot Poll → DevInfo → First Ready → Trip → continuous steady polling) — verified to release the **discharge MOSFETs** on BT-E6000 without bike present (battery powers a load via main contacts). `[Sim-Charger]` does the charger wake (HS-Pong → 80ms gap → Auth replay → Specs-Req → polls) — verified to release the **charge MOSFETs** when paired with a 41.5 V bench supply at the main contacts (state advances Init→Pre→Chg, Vbat climbs through IR-drop, no real Shimano charger needed). `[Shutdown]` cleanly powers the BMS down. |
| **Sim-BMS** | ESP32 impersonates the battery, responds to motor/charger requests with configurable fake telemetry (SOC, Vbat). Useful for testing motor/display behavior without an actual battery. |

### Hardware

ESP32 dev board, 3 wires to the battery connector (GND, B-TX → GPIO19, B-RX → GPIO18). Recommended: 5 kΩ pull-up on GPIO19 to 3.3V (stable UART idle when battery disconnected) and 5 kΩ pull-down on GPIO18 to GND (prevents accidental BMS wake while sniffing).

### Critical implementation details

1. **Inter-byte UART timing** — the BMS validates that bytes within a frame arrive with ~1-3 ms gaps. The TinyC code sends each byte via `serialWriteByte` with `delayMicroseconds(2500)` between calls. Sending whole frames via `serialWriteBytes(buf, len)` (back-to-back) is silently rejected by the BMS even with valid CRCs, returning a degraded `30 12` Auth-Resp and flipping fault byte to `0x15` after ~8 s.

2. **Inter-frame gap before charger Auth-Req** — in Sim-Charger mode, HS-Pong and Auth-Req must be sent as two **separate** UART transmissions with ~80 ms gap between them. Combined into a single 27-byte burst (even with proper inter-byte timing) the Auth-Req is silently ignored — battery only acknowledges the HS-Pong with `00 C1 00 35 DC`.

3. **Auth-Req replay must come from a real session of the same battery.** Random bytes with the correct structural format are silently rejected — the BMS validates more than just structure. For Sim-Charger especially, Auth-Req appears to be per-battery (bytes from one battery's session don't work on another's).

See [protocol_analysis/readme.md](protocol_analysis/README.md) for the full protocol decode.

### Deploy

Flash a Tasmota-TinyC build onto an ESP32 (instructions: gemu2015 repo above), then upload `Tasmota-TinyC/ShimanoSniffer.tc` via Tasmota's file manager. Restart, open the device's web UI, and the Shimano page appears in the menu.  
I also offer TinyC Ready Tasmota images on my other [repository](https://github.com/ottelo9/tasmota-sml-images).

## Useful Links
- https://github.com/michielvg
- https://github.com/michielvg/Shimano_BT-E6000_BMS/discussions
- https://github.com/gregyedlik/BT-E60xx
