# WiFi Frames

## Overview

Every WiFi frame has a header that contains a **type** (2 bits) and **subtype** (4 bits).
These two fields together tell you exactly what the frame is and what it's doing.

---

## Frame Types

| Type | Name       | Purpose                                      |
|------|------------|----------------------------------------------|
| 0    | Management | Control the network — connecting, advertising, disconnecting |
| 1    | Control    | Low-level helpers — ACK, RTS/CTS             |
| 2    | Data       | Actual traffic — web, streaming, anything    |

---

## Management Subtypes (type = 0)

| Subtype | Name                 | What it means                                      |
|---------|----------------------|----------------------------------------------------|
| 0x00    | Association Request  | Device asking to formally join an AP               |
| 0x01    | Association Response | AP accepting or rejecting the join                 |
| 0x04    | Probe Request        | Device broadcasting "is anyone out there?"         |
| 0x05    | Probe Response       | AP responding to a probe                           |
| 0x08    | Beacon               | AP constantly advertising its existence and SSID   |
| 0x0b    | Authentication       | Start of the connection handshake                  |
| 0x0c    | Deauth               | Forcibly disconnecting a device — can be an attack |
| 0x0d    | Action               | Misc management actions (spectrum, QoS, etc)       |

---

## Data Subtypes (type = 2)

| Subtype | Name      | What it means                                        |
|---------|-----------|------------------------------------------------------|
| 0x00    | Data      | Plain data frame                                     |
| 0x04    | Null      | Device telling AP "I'm alive" with no payload        |
| 0x08    | QoS Data  | Most modern traffic — same as Data but with QoS info |
| 0x0c    | QoS Null  | Keepalive with QoS info, no payload                  |

---

## Direction Flags (DS bits)

Data frames have two flags — `To DS` and `From DS` — that tell you which direction traffic is flowing.

| To DS | From DS | Meaning                        |
|-------|---------|--------------------------------|
| 1     | 0       | Client sending to AP           |
| 0     | 1       | AP sending to client           |
| 0     | 0       | Ad-hoc (device to device)      |
| 1     | 1       | Wireless bridge (AP to AP)     |

---

## What Yoda Captures

```
wlan.fc.type_subtype == 0x08  →  Beacons      (find APs)
wlan.fc.type == 2             →  Data frames  (find clients)
wlan.fc.type_subtype == 0x0c  →  Deauth       (attack detection)
```

---

## Frame Structure

Every WiFi frame is laid out in this order:

```
[ Frame Control | Duration | Address 1 | Address 2 | Address 3 | Sequence | Address 4 | Payload | FCS ]
```

- **Frame Control** — 2 bytes. Contains type, subtype, DS bits, and other flags
- **Duration** — how long the channel is reserved for this transmission
- **Address fields** — up to 4 MAC addresses (explained below)
- **Sequence** — frame number, used to detect duplicates and reorder packets
- **Payload** — the actual data (encrypted in modern networks)
- **FCS** — Frame Check Sequence, a checksum to detect corruption

---

## Address Fields

WiFi frames can carry up to 4 MAC address fields. Which ones are used and what they mean
depends on the DS bits.

| Field     | To DS=1, From DS=0 (client → AP) | To DS=0, From DS=1 (AP → client) |
|-----------|----------------------------------|----------------------------------|
| Address 1 | BSSID (destination AP)           | Client MAC (destination)         |
| Address 2 | Client MAC (source)              | BSSID (source AP)                |
| Address 3 | Final destination IP's MAC       | Original sender's MAC            |
| Address 4 | Only used in bridge mode         | Only used in bridge mode         |

This is why you can identify a client — Address 2 in a `To DS` frame is always the client's MAC.

---

## Encryption

The payload of a data frame is encrypted — you cannot read it without the key.

- **WEP** — old and broken, crackable in minutes
- **WPA/WPA2** — uses a 4-way handshake to derive a session key. You can capture the handshake and try to crack the password offline, but you can't read live traffic without the key
- **WPA3** — stronger handshake (SAE), much harder to crack even offline

Yoda only looks at headers — the payload is never touched or stored.

---

## RSSI (Signal Strength)

RSSI stands for Received Signal Strength Indicator. It's measured in **dBm** (decibel-milliwatts)
and is always a negative number. Closer to 0 = stronger signal.

| RSSI Range    | Quality     |
|---------------|-------------|
| -30 to -50    | Excellent   |
| -50 to -67    | Good        |
| -67 to -80    | Fair        |
| -80 to -90    | Poor        |
| Below -90     | Unusable    |

RSSI is not in the WiFi frame itself — it's added by your wireless adapter/driver as metadata
when it captures the packet. This is why you need monitor mode to see it.

---

## Things Worth Knowing

**Hidden SSIDs** — APs still broadcast beacon frames even when the SSID is hidden.
The SSID field is just blank. You still see the BSSID and any clients connecting to it.

**BSSID vs MAC** — An AP's BSSID is usually its MAC address, but some APs run multiple
SSIDs off one radio with slightly different BSSIDs (last byte increments by 1).

**Probe Requests** — Devices broadcast these hunting for saved networks even when not
connected to anything. You can detect a phone just from its probe requests.

**Channel hopping** — Since the adapter hops channels, you'll miss frames that happen
between hops. A client could connect and disconnect without you ever seeing it.
Shorter hop delay and more targeted hop list = better coverage.

**Passive only** — No packets are sent, nothing is injected. You're just listening
to what's already in the air.
