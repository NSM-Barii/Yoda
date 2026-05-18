# Bluetooth vs BLE — What's Actually Going On

## The Misconception

Most people think Bluetooth and BLE are the same thing or that BLE is just a newer
version of Bluetooth. They're not. They are two completely separate protocols that
happen to share a name and the 2.4 GHz band.

---

## History

- **Classic Bluetooth (BR/EDR)** — designed by Ericsson in the 90s, standardized in 1999
- **BLE** — designed from scratch by Nokia under the name "Wibree" around 2006, then
  adopted into the Bluetooth spec in 2010 with **Bluetooth 4.0**

Nokia built BLE to solve a specific problem Classic Bluetooth couldn't — ultra low power
communication for sensors and wearables that need to run on a coin battery for years.
The Bluetooth SIG absorbed it and rebranded it as "Bluetooth Low Energy" to keep everything
under one umbrella.

---

## They Cannot Talk To Each Other

A Classic Bluetooth device and a BLE-only device are **incompatible**. They cannot
communicate directly. The protocols are completely different at every layer — physical,
link, and application.

---

## Dual-Mode Chips

What you see in phones and laptops is a **dual-mode chip** — one piece of hardware with
two independent radios inside:

```
[ Bluetooth Chip ]
    ├── Classic Bluetooth radio  (BR/EDR)
    └── BLE radio
```

The OS abstracts both under a single "Bluetooth" toggle, so it looks like one system.
But underneath they are running completely separate stacks.

---

## Real World Example — AirPods

When you connect AirPods to an iPhone, two separate connections are made simultaneously:

| Connection | Protocol         | Purpose                        |
|------------|------------------|--------------------------------|
| Audio      | Classic Bluetooth | Streaming audio (A2DP profile) |
| Control    | BLE              | Pause, play, battery level, ear detection |

Two different protocols, two different connections, same chip, same "Bluetooth" toggle.

---

## Single-Mode Devices

Cheap IoT devices like sensors, beacons, and fitness trackers often only have a **BLE radio**.
They physically cannot communicate with Classic Bluetooth devices. They can only talk to
dual-mode devices (phones, laptops) via the BLE side of the chip.

---

## Quick Comparison

| Feature          | Classic Bluetooth  | BLE                        |
|------------------|--------------------|----------------------------|
| Designed by      | Ericsson (1990s)   | Nokia (2006)               |
| Added to spec    | Bluetooth 1.0      | Bluetooth 4.0 (2010)       |
| Power draw       | High               | Very low                   |
| Best for         | Audio, file transfer | Sensors, beacons, wearables |
| Cross-compatible | No                 | No                         |
| Passive sniffing | Harder             | Easy                       |

---

## Why It Matters for Yoda

When Yoda scans for BLE devices it only sees BLE advertising packets. Classic Bluetooth
devices that are not also broadcasting BLE will be invisible. A Bluetooth speaker with
no BLE radio won't show up at all. A pair of AirPods will show up because they broadcast
BLE even while streaming Classic Bluetooth audio.
