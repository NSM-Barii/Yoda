# THIS MODULE WILL HOUSE MONITORING CLASSESS FOR WiFi/Bluetooth/Evil_Twins/etc



# UI IMPORTS
from rich.table import Table
from rich.live import Live
from rich.panel import Panel


# NETWORK IMPORTS
from bleak import BleakClient, BleakScanner
from scapy.all import sniff, RadioTap, Ether, ARP, srp
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11AssoReq, Dot11ProbeReq, Dot11Elt, Dot11Deauth


# ETC IMPORTS
import asyncio, time, subprocess, time, threading
from datetime import datetime


# NSM IMPORTS
from nsm_vars import Variables
from nsm_database import DataBase, Extensions, Background_Threads
# from nsm_modules.nsm_utilities import Utilities, Connection_Handler


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
                            data = f"[bold green][{cls.devices}][/bold green] [cyan]{mac}[/cyan]  [yellow]{name or '?'}[/yellow]  [dim]{vendor or manuf or ''}[/dim]  rssi:[bold]{rssi}[/bold]"
                            Variables.tui.call_from_thread(Variables.tui.push_data, "#ble", data)
                            Variables.tui.call_from_thread(Variables.tui.upsert_ble, mac, vendor, manuf, name, rssi)
                    
                        

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
                        data = (f"{use}[yellow] rssi spike")
                        Variables.tui.call_from_thread(Variables.tui.push_data, "#ble", data)

                    if (time_missing > 5): 
                        weight += 1
                        #console.print(f"{use}[yellow] short time gap")

                    if (time_missing > 10): 
                        weight += 2
                        data = (f"{use}[yellow] long time gap")
                        Variables.tui.call_from_thread(Variables.tui.push_data, "#ble", data)


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
                                data = (f"[bold green][+] Device now stable:[yellow] {mac}")
                                Variables.tui.call_from_thread(Variables.tui.push_data, "#ble", data)

                                # Voice notification
                                Variables.push_event(f"Device stabilized")



                    """
                    Proverbs 27:17 As iron sharpens iron, so a friend sharpens another.
                    """



                    if time_missing > 30:
                        data = (f"[bold yellow][-] Removing stale device:[/bold yellow] {mac}")
                        Variables.tui.call_from_thread(Variables.tui.push_data, "#ble", data)
                        dev_data = dev["data"]
                        Variables.tui.call_from_thread(Variables.tui.upsert_ble, mac, dev_data.get("vendor"), dev_data.get("manuf"), dev_data.get("name"), dev_data.get("rssi"), "offline")
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
                    data = (f"[bold green][!] New BLE max:[/bold green] {total} devices")
                    Variables.tui.call_from_thread(Variables.tui.push_data, "#ble", data)
                    Variables.push_event(f"New maximum. {total} Bluetooth devices detected")

                if total < Variables.ble_min:
                    Variables.ble_min = total
                    data = (f"[bold red][!] New BLE min:[/bold red] {total} devices")
                    Variables.tui.call_from_thread(Variables.tui.push_data, "#ble", data)
                    Variables.push_event(f"Alert. Device count dropped to {total} Bluetooth devices")

                wifi_aps    = len(Variables.live_map_wifi)
                wifi_clients = sum(len(d["clients"]) for d in Variables.live_map_wifi.values() if "clients" in d)
                Variables.tui.call_from_thread(Variables.tui.update_stats, total, wifi_aps, wifi_clients)



        except KeyboardInterrupt as e:  
            data = (f"[bold red][!] BLE Keyboard Exception Error:[bold yellow] {e}")
            Variables.tui.call_from_thread(Variables.tui.push_data, "#ble", data)
        except Exception as e:          
            data = (f"[bold red][!] BLE Exception Error:[bold yellow] {e}")
            Variables.tui.call_from_thread(Variables.tui.push_data, "#ble", data)


    @classmethod
    def main(cls):
        """Run from here"""


        #if not Variables.monitor: return False
        

        cls.devices = 0
        cls.num = 0

        cls.live_map = Variables.live_map_bt


        try: 
            
            data = ("[yellow][+] Bluetooth/BLE Monitoring Activated")
            Variables.tui.call_from_thread(Variables.tui.push_data, "#ble", data)
            asyncio.run(cls._ble_printer(server_ip=False))
    
        except KeyboardInterrupt: 
            data = ("\n[bold red]Stopping....")
            Variables.tui.call_from_thread(Variables.tui.push_data, "#ble", data)
        except Exception as e: 
            data = (f"[bold red]Sniffer Exception Error:[bold yellow] {e}")
            Variables.tui.call_from_thread(Variables.tui.push_data, "#ble", data)


# Tshark WRAPPER 
class Monitor_WiFi():
    """This will track WiFi APs and clients"""


    DataBase = DataBase.WiFi


    @classmethod
    def _scanner(cls, iface):

        cmd = [
            "tshark", "-i", iface, "-l",
            "-Y", "wlan.fc.type_subtype == 0x08 || wlan.fc.type == 2",
            "-T", "fields",
            "-e", "wlan.ta",
            "-e", "wlan.ra",
            "-e", "wlan.ssid",
            "-e", "radiotap.dbm_antsignal",
            "-e", "wlan_radio.channel",
            "-e", "wlan.fc.type_subtype",
        ]

        process = subprocess.Popen(
            cmd, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.DEVNULL, 
            text=True
            )

        try:

            for line in process.stdout:

                parts = line.strip().split("\t")
                if len(parts) < 6: continue

                src     = parts[0]
                dst     = parts[1]
                raw     = parts[2].strip()
                rssi    = max((int(x) for x in parts[3].split(",") if x), default=-100)
                channel = parts[4]

                try:    ft = int(parts[5].strip(), 0)
                except: ft = -1

                if not src or src == "ff:ff:ff:ff:ff:ff": continue


                if ft == 0x08:

                    if raw:
                        try:    ssid = bytes.fromhex(raw).decode("utf-8", errors="ignore")
                        except: ssid = raw
                    else: ssid = "Hidden"

                    if src not in cls.live_map:

                        vendor = cls.DataBase.get_vendor_main(mac=src, verbose=False)
                        cls.live_map[src] = {"ssid": ssid, "channel": channel, "rssi": rssi, "vendor": vendor, "clients": set()}

                        cls.aps += 1
                        data = f"[bold green][SSID][/bold green] [cyan]{ssid}[/cyan]  [dim]{src}[/dim]  ch:[bold]{channel}[/bold]  rssi:[bold]{rssi}[/bold]  [dim]{vendor or ''}[/dim]"
                        Variables.tui.call_from_thread(Variables.tui.push_data, "#wifi", data)
                        Variables.tui.call_from_thread(Variables.tui.upsert_ap, src, ssid, vendor, channel, rssi, 0)
                        Variables.tui.call_from_thread(Variables.tui.add_ap_to_tree, src, ssid, rssi)

                        total = len(cls.live_map)
                        Variables.tui.call_from_thread(Variables.tui.update_stats, len(Variables.live_map_bt), total, 0)


                else:  

                    ap_mac     = src if src in cls.live_map else (dst if dst in cls.live_map else None)
                    client_mac = dst if ap_mac == src else src

                    if not ap_mac or not client_mac or client_mac == "ff:ff:ff:ff:ff:ff": continue
                    if client_mac in cls.live_map: continue  

                    if client_mac not in cls.live_map[ap_mac]["clients"]:

                        cls.live_map[ap_mac]["clients"].add(client_mac)
                        vendor       = cls.DataBase.get_vendor_main(mac=client_mac, verbose=False)
                        ap           = cls.live_map[ap_mac]
                        client_count = len(ap["clients"])

                        data = f"[bold yellow][CLIENT][/bold yellow] [yellow]{client_mac}[/yellow]  ->  [cyan]{ap['ssid']}[/cyan]  [dim]{vendor or ''}[/dim]"
                        Variables.tui.call_from_thread(Variables.tui.push_data, "#wifi", data)
                        Variables.tui.call_from_thread(Variables.tui.add_client_to_tree, ap_mac, client_mac, vendor)
                        Variables.tui.call_from_thread(Variables.tui.upsert_ap, ap_mac, ap["ssid"], ap["vendor"], ap["channel"], ap["rssi"], client_count)

                        total_clients = sum(len(d["clients"]) for d in cls.live_map.values())
                        Variables.tui.call_from_thread(Variables.tui.update_stats, len(Variables.live_map_bt), len(cls.live_map), total_clients)


        except Exception as e: Variables.tui.call_from_thread(Variables.tui.push_data, "#wifi", f"[bold red][!] WiFi Error:[/bold red] {e}")
        finally: process.kill()


    @classmethod
    def main(cls):

        cls.aps      = 0
        cls.live_map = Variables.live_map_wifi
        iface        = Variables.iface_monitor

        Variables.tui.call_from_thread(Variables.tui.push_data, "#wifi", "[yellow][+] WiFi Monitoring Active")
        Background_Threads.channel_hopper()
        cls._scanner(iface=iface)





class Monitor_LAN():
    """This class will be responsible for finding local devices and tracking their connection status"""
    

    DataBase = DataBase.WiFi



    @classmethod
    def subnet_scanner(cls, iface, target="192.168.1.0/24"):
        """This will perform an ARP scan"""


        c1 = "bold red"
        c2 = "bold green"
        c3 = "bold yellow"
        num = 0


        while True:

            try:

                arp      = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(target))
                response = srp(arp, iface=iface, timeout=5, verbose=0)[0]
                now      = time.time()


                for sent, recv in response:

                    target_ip  = recv.psrc
                    target_mac = recv.hwsrc


                    if target_ip not in cls.live_map:

                        host   = cls.DataBase.get_host_name(target_ip=target_ip)
                        vendor = cls.DataBase.get_vendor_main(mac=target_mac)

                        cls.live_map[target_ip] = {
                            "target_ip":   target_ip,
                            "target_mac":  target_mac,
                            "host":        host,
                            "vendor":      vendor,
                            "first_seen":  now,
                            "last_seen":   now
                        }

                        cls.devices += 1
                        data = (f"[{c2}][+][/{c2}] [{c3}]{target_ip}[/{c3}]  {host}  {vendor}")
                        Variables.tui.call_from_thread(Variables.tui.push_data, "#lan", data)
                        Variables.push_event(f"New LAN device. {host} {target_ip}")

                        threading.Thread(target=Connection_Handler.status_checker, args=(target_ip, target_mac, host, vendor, iface), daemon=True).start()

                    else:
                        cls.live_map[target_ip]["last_seen"] = now


                num += 1
                time.sleep(cls.scan_delay)


            except Exception as e:
                data = (f"[{c1}][!] LAN Scanner Error:[bold yellow] {e}")
                Variables.tui.call_from_thread(Variables.tui.push_data, "#lan", data)
                Connection_Handler.establish_reconnection(verbose=False)
                time.sleep(5)



    @classmethod
    def main(cls):
        """This will be responsible for performing class wide logic"""


        cls.devices    = 0
        cls.scan_delay = 10
        cls.live_map   = Variables.live_map_lan
        iface          = Variables.iface_monitor
        subnet         = Variables.subnet

        try:
            data = ("[yellow][+] LAN Monitoring Active")
            Variables.tui.call_from_thread(Variables.tui.push_data, "#lan", data)
            cls.subnet_scanner(iface=iface, target=subnet)

        except KeyboardInterrupt:
            data = ("\n[bold red]Stopping....")
            Variables.tui.call_from_thread(Variables.tui.push_data, "#lan", data)
        except Exception as e:
            data = (f"[bold red]LAN Monitor Exception Error:[bold yellow] {e}")
            Variables.tui.call_from_thread(Variables.tui.push_data, "#lan", data)
        






class Monitor_Runner():
    """This class will run module classess"""


    @staticmethod
    def main():
        """Run module classess"""



        threading.Thread(target=Monitor_Bluetooth.main, args=(), daemon=True).start()

        threading.Thread(target=Monitor_WiFi.main,      args=(), daemon=True).start()

        #threading.Thread(target=Monitor_LAN.main,       args=(), daemon=True).start()





# tshark -i wlan1 -l -Y "wlan.fc.type_subtype == 0x0c"


# FOR MODULAR TESTING ONLY
if __name__ == "__main__":
    
    Monitor_Runner.main()
    #Monitor_WiFi.main()
    # Monitor_Bluetooth.main()