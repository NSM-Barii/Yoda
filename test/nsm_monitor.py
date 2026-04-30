# THIS MODULE WILL HOUSE MONITORING CLASSESS FOR WiFi/Bluetooth/Evil_Twins/etc



# UI IMPORTS
from rich.table import Table
from rich.live import Live
from rich.panel import Panel


# NETWORK IMPORTS
from bleak import BleakClient, BleakScanner
from scapy.all import sniff, RadioTap
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11AssoReq, Dot11ProbeReq, Dot11Elt, Dot11Deauth


# ETC IMPORTS
import asyncio, time, subprocess, time, threading
from datetime import datetime


# NSM IMPORTS
from nsm_vars import Variables
from nsm_database import DataBase, Extensions, Background_Threads


# CONSTANTS
console = Variables.console
LOCK    = Variables.LOCK
#DataBase = DataBase.Bluetooth




# REMASTERED <-- Bluehound
class Monitor_Bluetooth(): 
    """This will be a ble hacking framework"""



    DataBase = DataBase.Bluetooth



    @classmethod
    async def _ble_discover(cls):
        """This will sniff traffic"""


        devices = await BleakScanner.discover(timeout=60, return_adv=True)

        return devices
    
    
    @classmethod
    def _get_manuf(cls, manuf):
        """This will parse and get manuf"""


    
        if not manuf: return False

        for key, value in manuf.items():
            id = key; hex = value.hex()
        
        company = cls.DataBase.get_manufacturer(id=id, data=hex)
        return company


    @classmethod
    async def _ble_printer(cls, server_ip=False) -> None:
        """Lets enumerate"""


        c1 = "bold red"
        c2 = "bold yellow"
        c3 = "bold green"
        c4 = "bold red"
        c5 = "bold blue"
        table = ""
        cycle = 0
        unstable_devices = set()
        panel = Panel(renderable="Developed by nsm_barii", style="bold red", border_style="bold purple", expand=False)

        table = Table(title="BLE Driving", title_style="bold red", border_style="bold purple", style="bold purple", header_style="bold red")
        table.add_column("#"); table.add_column("RSSI", style=c2); table.add_column("Mac", style=c3); table.add_column("Manufacturer", style=c5); table.add_column("Local_name"); table.add_column("UUID", style=c3)


        try:

            scanner = BleakScanner()
            
            #with Live(panel, console=console, refresh_per_second=4):

            while True:


                await scanner.start()
                await asyncio.sleep(5)
                await scanner.stop()
                devices = scanner.discovered_devices_and_advertisement_data
                now     = time.time()
                cycle   += 1



                if devices: 
                
                    
                    for mac, (device, adv) in devices.items():
                        
                        name  = adv.local_name or False
                        rssi  = adv.rssi
                        uuid  = adv.service_uuids or False
                        manuf = cls._get_manuf(manuf=adv.manufacturer_data) 
                        vendor = cls.DataBase.get_vendor_main(mac=mac, verbose=False) 
                                        

                        data = {
                            "rssi": rssi,
                            "addr": mac,
                            "manuf": manuf,
                            "vendor": vendor,
                            "name": name,
                            "uuid": uuid,
                        }

                        

                        if (mac not in cls.live_map):
                            
            
                            cls.live_map[mac] = {
                                "status": "stable",
                                "data": data,
                                "rssi_list": [],
                                "unstable_hits": 0,
                                "seen_cycles": 1,
                                "first_seen": now,
                                "last_seen": now
                            }

                            cls.devices += 1
                            console.print(f"{cls.devices}", rssi, mac, manuf, vendor, name, uuid)
                    
                        


                        cls.live_map[mac]["rssi_list"].append(rssi)
                        cls.live_map[mac]["seen_cycles"] += 1
                        cls.live_map[mac]["last_seen"]   = now
                        cls.live_map[mac]["cycle"]       = cycle

                for mac, dev in list(cls.live_map.items()):
                        
                    use = f"[dim][>] {mac} ->"
                    weight       = 0
                    rssi_list    = dev["rssi_list"]
                    time_missing = now - dev["last_seen"]


                    
                    # // C++ IS SUPERIOR
                    if len(rssi_list) >= 3 and max(rssi_list) - min(rssi_list) > 30: 
                        weight += 1
                        console.print(f"{use}[yellow] rssi spike")

                    if (time_missing > 5): 
                        weight += 1
                        #console.print(f"{use}[yellow] short time gap")

                    if (time_missing > 10): 
                        weight += 2
                        console.print(f"{use}[yellow] long time gap")


                    if (weight >= 2): dev["unstable_hits"] += 1
                    else:           
                        if dev["unstable_hits"] > 0:
                            dev["unstable_hits"] -= 1


                    if (dev["unstable_hits"] >= 2):
                        if dev["status"] != "unstable":
                            console.print(f"[bold red][!] Unstable Device:[yellow] {mac}")
                            unstable_devices.add(mac)
                            dev["status"] = "unstable"
                            dev["stable_count"] = 0

                            # Voice notification
                            vendor = dev["data"].get("vendor") or "Unknown"
                            Variables.push_event(f"Alert. Unstable BLE device detected. {vendor}")

                    else:
                        if (dev["status"] == "unstable"):
                            dev["stable_count"] += 1

                            if (dev["stable_count"] >= 2):
                                dev["status"] = "stable"
                                dev["stable_count"] = 0
                                unstable_devices.discard(mac)
                                console.print(f"[bold green][+] Device now stable:[yellow] {mac}")

                                # Voice notification
                                Variables.push_event(f"Device stabilized")



                    """
                    Proverbs 27:17 As iron sharpens iron, so a friend sharpens another.
                    """



                    if time_missing > 30:
                        console.print(f"[bold yellow][-] Removing stale device:[/bold yellow] {mac}")
                        unstable_devices.discard(mac)
                        del cls.live_map[mac]


        

                

                # WILL MAKE A GLOBALIZED SAVE FOR ALL INFO FROM ALL MONITOR METHODS
                # DataBase.push_results(devices=cls.war_drive, verbose=False)

                                    
                count = len(devices) if devices else 0
                Extensions.Controller(current_count=count, server_ip=server_ip)

                avg       = Extensions.avg or 1
                total     = len(cls.live_map) or 1
                unstables = len({mac for mac in unstable_devices if mac in cls.live_map})

                unstable_ratio = unstables / total
                drop_score     = (avg - count) / avg if avg else 0

                unstable_pct = round(unstable_ratio * 100, 2)
                drop_pct     = round(drop_score * 100, 2)

                c1 = "bold yellow"
                panel.renderable = (
                    f"Session Devices:[{c1}] {total}[/{c1}]  -  "
                    f"Unstable Devices:[{c1}] {unstables}[/{c1}]  -  "
                    f"Unstable Ratio:[{c1}] {unstable_pct}%[/{c1}]  -  "
                    f"Drop Score:[{c1}] {drop_pct}%[/{c1}]"
                )


                Variables.ble_current = total

                if total > Variables.ble_max:
                    Variables.ble_max = total
                    console.print(f"[bold green][!] New BLE max:[/bold green] {total} devices")
                    Variables.push_event(f"New maximum. {total} Bluetooth devices detected")

                if total < Variables.ble_min:
                    Variables.ble_min = total
                    console.print(f"[bold red][!] New BLE min:[/bold red] {total} devices")
                    Variables.push_event(f"Alert. Device count dropped to {total} Bluetooth devices")



        except KeyboardInterrupt as e:  console.print(f"[bold red][!] BLE Keyboard Exception Error:[bold yellow] {e}")
        except Exception as e:          console.print(f"[bold red][!] BLE Exception Error:[bold yellow] {e}")


    @classmethod
    def main(cls):
        """Run from here"""


        #if not Variables.monitor: return False
        

        cls.devices = 0
        cls.num = 0

        cls.live_map = Variables.live_map_bt


        try: 
            
            console.print("[yellow][+] Bluetooth/BLE Monitoring Activated")
            asyncio.run(cls._ble_printer(server_ip=server_ip))
    
        except KeyboardInterrupt: console.print("\n[bold red]Stopping....")
        except Exception as e: console.print(f"[bold red]Sniffer Exception Error:[bold yellow] {e}")


# Tshark WRAPPER 
class Monitor_WiFi():
    """This will track WiFi APs and their clients"""


    DataBase = DataBase.WiFi


    @classmethod
    def _pkt_handler(cls, iface):
        """This will sniff for beacons and data frames to track APs and clients"""


        cmd = [
            "tshark",
            "-i", iface,
            "-l",
            "-T", "fields",
            "-e", "wlan.fc.type_subtype",
            "-e", "wlan.sa",
            "-e", "wlan.da",
            "-e", "wlan.bssid",
            "-e", "wlan.ssid",
            "-e", "radiotap.dbm_antsignal",
            "-Y", "wlan.fc.type_subtype == 0x08 || wlan.fc.type == 2 || wlan.fc.type_subtype == 0x0c"
        ]


        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
        )


        c1 = "bold red"
        c2 = "bold green"
        c3 = "bold yellow"
        cycle = 0
        unstable_aps = set()
        last_check = time.time()
        deauth_tracker = {}
        last_deauth_check = time.time()

        try:

            for line in process.stdout:

                parts = line.strip().split("\t")
                if len(parts) < 4: continue

                frame_type = parts[0]
                src = parts[1] if len(parts) > 1 else None
                dst = parts[2] if len(parts) > 2 else None
                bssid = parts[3] if len(parts) > 3 else None
                ssid = parts[4] if len(parts) > 4 and parts[4] else "Hidden"
                rssi = parts[5] if len(parts) > 5 and parts[5] else None
                now = time.time()


                if frame_type == "0x0008":

                    try:
                        rssi_val = int(rssi) if rssi and rssi != "N/A" else -100
                    except: rssi_val = -100

                    if bssid not in cls.live_map:

                        vendor = cls.DataBase.get_vendor_main(mac=bssid, verbose=False)

                        cls.live_map[bssid] = {
                            "status": "stable",
                            "data": {"ssid": ssid, "rssi": rssi_val, "vendor": vendor},
                            "unstable_hits": 0,
                            "seen_cycles": 1,
                            "first_seen": now,
                            "last_seen": now,
                            "clients": set(),
                            "client_max": 0,
                            "client_min": 0
                        }

                        cls.aps += 1
                        console.print(f"{cls.aps}", rssi_val, bssid, ssid, vendor)

                    cls.live_map[bssid]["seen_cycles"] += 1
                    cls.live_map[bssid]["last_seen"] = now


                elif frame_type.startswith("0x") and bssid:
                    if bssid in cls.live_map:

                        client_mac = src if src != bssid else dst

                        if client_mac and client_mac not in cls.live_map[bssid]["clients"] and client_mac != "ff:ff:ff:ff:ff:ff":
                            cls.live_map[bssid]["clients"].add(client_mac)
                            vendor = cls.DataBase.get_vendor_main(mac=client_mac, verbose=False)

                            console.print(f"[{c3}][*] New Client:[/{c3}] {client_mac} -> AP: {cls.live_map[bssid]['data']['ssid']} ({vendor})")

                            ap_name = cls.live_map[bssid]['data']['ssid']
                            Variables.push_event(f"New client connected to {ap_name}")


                elif frame_type == "0x000c":

                    if src not in deauth_tracker:
                        deauth_tracker[src] = {"count": 0, "start_time": now, "dst": set()}

                    deauth_tracker[src]["count"] += 1
                    deauth_tracker[src]["dst"].add(dst)

                    time_elapsed = now - deauth_tracker[src]["start_time"]

                    if time_elapsed >= 1 and deauth_tracker[src]["count"] >= 5:
                        rate = deauth_tracker[src]["count"] / time_elapsed
                        targets = len(deauth_tracker[src]["dst"])

                        console.print(f"[{c1}][!] Deauth Attack Detected![/{c1}]"
                                    f"\n     [{c3}]Attacker:[/{c3}] {src}"
                                    f"\n     [{c3}]Rate:[/{c3}] {int(rate)} pkts/sec"
                                    f"\n     [{c3}]Targets:[/{c3}] {targets}\n")

                        Variables.push_event(f"Warning. Deauth attack detected. {int(rate)} packets per second from {src}")

                        deauth_tracker[src]["count"] = 0
                        deauth_tracker[src]["start_time"] = now


                if now - last_deauth_check >= 10:
                    for src in list(deauth_tracker.keys()):
                        if now - deauth_tracker[src]["start_time"] > 10:
                            del deauth_tracker[src]
                    last_deauth_check = now


                if now - last_check >= 5:
                    cycle += 1

                    for bssid, dev in list(cls.live_map.items()):

                        time_missing = now - dev["last_seen"]
                        client_count = len(dev["clients"])
                        ssid_name = dev["data"]["ssid"]

                        if client_count > dev["client_max"]:
                            dev["client_max"] = client_count
                            console.print(f"[bold green][!] {ssid_name} new client max:[/bold green] {client_count}")
                            Variables.push_event(f"New maximum. {ssid_name} has {client_count} clients")

                        if client_count < dev["client_min"]:
                            dev["client_min"] = client_count
                            console.print(f"[bold red][!] {ssid_name} new client min:[/bold red] {client_count}")
                            Variables.push_event(f"Alert. {ssid_name} client count dropped to {client_count}")

                        if time_missing > 10:
                            if dev["status"] != "offline":
                                console.print(f"[bold red][!] AP Offline:[yellow] {ssid_name} ({bssid})")
                                dev["status"] = "offline"
                                Variables.push_event(f"Alert. Access point offline. {ssid_name}")
                        else:
                            if dev["status"] == "offline":
                                console.print(f"[bold green][+] AP Back Online:[yellow] {ssid_name} ({bssid})")
                                dev["status"] = "stable"
                                unstable_aps.discard(bssid)
                                Variables.push_event(f"Access point back online. {ssid_name}")

                        if time_missing > 30:
                            console.print(f"[bold yellow][-] Removing stale AP:[/bold yellow] {bssid}")
                            unstable_aps.discard(bssid)
                            del cls.live_map[bssid]


                    total = len(cls.live_map) or 1
                    unstables = len({bssid for bssid in unstable_aps if bssid in cls.live_map})
                    unstable_ratio = unstables / total
                    unstable_pct = round(unstable_ratio * 100, 2)

                    console.print(f"[bold yellow]Session APs:[/bold yellow] {total}  -  [bold yellow]Unstable:[/bold yellow] {unstables} ({unstable_pct}%)")

                    Variables.wifi_current = total

                    if total > Variables.wifi_max:
                        Variables.wifi_max = total
                        console.print(f"[bold green][!] New WiFi max:[/bold green] {total} APs")
                        Variables.push_event(f"New maximum. {total} WiFi access points detected")

                    if total < Variables.wifi_min:
                        Variables.wifi_min = total
                        console.print(f"[bold red][!] New WiFi min:[/bold red] {total} APs")
                        Variables.push_event(f"Alert. Access point count dropped to {total}")

                    last_check = now

        except KeyboardInterrupt as e: console.print(f"[bold red][!] WiFi Keyboard Exception Error:[bold yellow] {e}")
        except Exception as e: console.print(f"[bold red][!] WiFi Exception Error:[bold yellow] {e}")



    @classmethod
    def main(cls):
        """This will run class wide logic"""

        cls.aps = 0
        cls.live_map = Variables.live_map_wifi
        iface = Variables.iface

        try:
            console.print("[yellow][+] WiFi AP & Client Monitoring Active")
            cls._pkt_handler(iface=iface)

        except KeyboardInterrupt: console.print("\n[bold red]Stopping....")
        except Exception as e: console.print(f"[bold red]WiFi Monitor Exception Error:[bold yellow] {e}")




class Monitor_Runner():
    """This class will run module classess"""


    @staticmethod
    def main():
        """Run module classess"""



        threading.Thread(target=Monitor_Bluetooth.main, args=(), daemon=True).start()

        threading.Thread(target=Monitor_WiFi.main,      args=(), daemon=True).start()



        while True: time.sleep(1)



# tshark -i wlan1 -l -Y "wlan.fc.type_subtype == 0x0c"


# FOR MODULAR TESTING ONLY
if __name__ == "__main__":
    
    Monitor_Runner.main()
    #Monitor_WiFi.main()
    # Monitor_Bluetooth.main()