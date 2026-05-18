# Bluetooth & BLE Frames

## Overview

Bluetooth has two main modes:

- **Classic Bluetooth (BR/EDR)** — older, higher power, used for audio (headphones, speakers)
- **BLE (Bluetooth Low Energy)** — newer, low power, used for sensors, wearables, IoT devices

Yoda focuses on **BLE** since it's far more common in passive monitoring scenarios.

---

## How BLE Works

BLE devices communicate on **40 channels** in the 2.4 GHz band:

- **3 advertising channels** — 37, 38, 39. Used to announce presence and accept connections
- **37 data channels** — used after a connection is established

When a BLE device wants to be discovered it broadcasts **advertising packets** on channels
37, 38, and 39 in rotation. This is what Yoda captures — no connection needed.

---

## Advertising Packet Types

| Type         | Name                        | What it means                                              |
|--------------|-----------------------------|------------------------------------------------------------|
| ADV_IND      | Connectable Undirected      | "I exist and anyone can connect to me"                     |
| ADV_DIRECT   | Connectable Directed        | "I exist and I want a specific device to connect"          |
| ADV_NONCONN  | Non-Connectable Undirected  | "I exist but you cannot connect to me" (beacons, sensors)  |
| ADV_SCAN     | Scannable Undirected        | "I exist, you can ask me for more info"                    |
| SCAN_REQ     | Scan Request                | Scanner asking for more info from an advertiser            |
| SCAN_RSP     | Scan Response               | Advertiser responding with extra data (name, services)     |

---

## BLE Packet Structure

```
[ Preamble | Access Address | PDU Header | PDU Payload | CRC ]
```

- **Preamble** — 1 byte, used for clock sync
- **Access Address** — 4 bytes. `0x8E89BED6` for advertising, unique per connection for data
- **PDU Header** — contains the advertising type and flags
- **PDU Payload** — the actual advertising data (name, services, manufacturer data, etc)
- **CRC** — 3 byte checksum

---

## PDU Payload Fields

The payload carries a list of data structures. Each one has a type tag:

| Tag    | Name                  | What it contains                              |
|--------|-----------------------|-----------------------------------------------|
| 0x01   | Flags                 | LE mode, discoverability                      |
| 0x08   | Shortened Local Name  | Device name (short version)                   |
| 0x09   | Complete Local Name   | Full device name                              |
| 0xFF   | Manufacturer Data     | Vendor-specific data (Apple uses this a lot)  |
| 0x02   | 16-bit Service UUIDs  | What services the device offers               |
| 0x0A   | TX Power Level        | Transmit power, used to estimate distance     |

---

## MAC Addresses in BLE

BLE devices can use two types of MAC addresses:

- **Public** — fixed, globally unique, tied to the hardware (like WiFi MACs)
- **Random** — rotates periodically to prevent tracking

Most modern phones and laptops use **random MACs** for BLE advertising, which means
the same device will appear as a different MAC every few minutes. This is why phone
tracking via BLE alone is unreliable.

IoT devices and wearables usually use a **public fixed MAC** so you can track them consistently.

---

## OUI (Vendor Identification)

The first 3 bytes of a MAC address are the OUI — Organizationally Unique Identifier.
This tells you who made the hardware.

Example: `A4:C3:F0` → Google, `DC:A6:32` → Raspberry Pi Foundation

Yoda uses an OUI database to resolve vendor names from the MAC. This is why you can
see "Apple" or "Samsung" next to a device even without knowing what it is.

Random MACs often won't resolve to a vendor since they're not registered.

---

## RSSI in BLE

Same concept as WiFi — measured in dBm, always negative, closer to 0 = stronger.

| RSSI Range  | Approximate Distance |
|-------------|----------------------|
| -40 to -55  | Very close (< 1m)    |
| -55 to -67  | Close (1-3m)         |
| -67 to -80  | Medium (3-10m)       |
| -80 to -90  | Far (10-30m)         |
| Below -90   | Very far or obstructed |

BLE RSSI is notoriously noisy — walls, interference, and device orientation all affect it heavily.
Use it as a rough indicator, not a precise measurement.

---

## Classic Bluetooth vs BLE

| Feature        | Classic Bluetooth      | BLE                        |
|----------------|------------------------|----------------------------|
| Power          | High                   | Very low                   |
| Range          | ~10-100m               | ~10-100m                   |
| Speed          | Up to 3 Mbps           | Up to 2 Mbps               |
| Use cases      | Audio, file transfer   | Sensors, wearables, beacons |
| Advertising    | Inquiry scan           | Advertising channels 37-39 |
| Passive scan   | Harder                 | Easy                       |

---

## Things Worth Knowing

**You don't need to connect** — advertising packets are broadcast openly. Yoda captures
them passively with no interaction with the device whatsoever.

**Scan response matters** — a device may advertise with no name, but if you send a SCAN_REQ
it responds with its full name. Yoda doesn't do active scanning so you may see unnamed devices.

**2.4 GHz interference** — BLE and WiFi share the same 2.4 GHz band. Heavy WiFi traffic
can interfere with BLE reception, especially on channels 1, 6, and 11 which overlap with
BLE advertising channels 37, 38, 39.

**Apple devices** — iPhones heavily use manufacturer data (0xFF) with a custom Apple format.
The first 2 bytes after the tag identify the Apple device type (AirDrop, AirPods, Find My, etc).

**Passive only** — Yoda only listens. No scan requests, no connections, no packets sent.
