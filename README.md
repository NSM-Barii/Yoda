<p align="center">
  <img src="banner.gif" alt="Yoda" width="100%"/>
</p>

# Yoda

Passive RF monitoring for home. Tracks BLE devices, WiFi access points, and clients in your area in real time — with push notifications and jamming detection.

Just run it — a CLI will walk you through all settings before launching the TUI.

```bash
sudo venv/bin/python main.py
```

---

## What it monitors

**Bluetooth / BLE**
- Discovers nearby devices with vendor and manufacturer lookup
- Tracks signal strength (RSSI) per device
- Detects unstable devices (randomized/rotating MACs)
- Jamming detection via asymmetric EWMA drop score
- New max / min device count alerts

**WiFi — Access Points**
- Passive channel-hopping scan across 2.4GHz and 5GHz
- SSID, BSSID, channel, vendor, client count per AP
- New AP alerts

**WiFi — Clients**
- Tracks clients associating with nearby APs
- Three-state presence: online → idle → offline
- Session duration tracking
- Alerts when clients leave and return

---

## TUI

Four tabs — live dashboard, BLE device table, WiFi AP table, WiFi tree (APs with clients nested underneath).

```
┌─────────────────────────────────────────────────────────┐
│  BLE: 12  |  APs: 8  |  Clients: 3                     │
├─────────────────────────────────────────────────────────┤
│  Dashboard │ BLE Devices │ WiFi APs │ WiFi Tree         │
├──────────────────────┬──────────────────────────────────┤
│  Bluetooth/BLE       │  WiFi                            │
│                      │                                  │
│  live feed...        │  live feed...                    │
└──────────────────────┴──────────────────────────────────┘
```

---

## Push Notifications (ntfy)

Alerts route to your phone via [ntfy.sh](https://ntfy.sh). Set a topic and install the ntfy app — no account needed.

```bash
python main.py -i wlan1 -ntfy my-topic-123
```

| Event | Priority |
|---|---|
| New BLE device | low |
| Unstable BLE device | max |
| BLE drop score rising | max |
| BLE instability alert | max |
| New WiFi AP | max |
| New client | max |
| Client left | max |
| Client returned | default |

---

## Jamming Detection

Yoda tracks a rolling average of visible BLE devices using an asymmetric EWMA:
- Average adapts **slowly** when count drops (`α = 0.01`) — sustained jamming doesn't let the baseline self-correct
- Average adapts **faster** when count rises (`α = 0.05`) — recovers cleanly after jamming stops

When the drop score or unstable device ratio exceeds your configured threshold, an alert fires. It won't re-fire until the metric recovers below half the threshold.

---

## Install

```bash
git clone https://github.com/nsm-barii/yoda
cd yoda/test
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Requires a wireless adapter that supports monitor mode.

---

## Usage

Flags are optional. Pass them to skip the prompt for that setting, or just set everything interactively.

```
sudo venv/bin/python main.py -i wlan1
sudo venv/bin/python main.py -i wlan1 -ntfy my-topic-123
sudo venv/bin/python main.py -i wlan1 -ntfy my-topic-123 --bu 30 --bd 40
sudo venv/bin/python main.py -help
```

| Flag | Description | Default |
|---|---|---|
| `-i` | Monitor mode interface | `wlan1` |
| `-ntfy` | ntfy topic for push notifications | off |
| `--bu` | BLE unstable device threshold % | 25 |
| `--bd` | BLE drop score threshold % | 25 |

---

## Files

```
main.py          — entry point, CLI arg parsing
nsm_tui.py       — Textual TUI + CLI setup flow
nsm_monitor.py   — BLE and WiFi monitor logic
nsm_database.py  — vendor lookup, notifications, EWMA
nsm_vars.py      — shared state and variables
```

---

Made by NSM Barii
