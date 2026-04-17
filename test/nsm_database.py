# THIS METHOD WILL BE RESPONSIBLE FOR IMPORTING SHIT VIA DATABASE DIR



# IMPORTS
import json, socket, manuf, requests, subprocess, threading, time
from pathlib import Path
from scapy.all import RadioTap
from scapy.layers.dot11 import Dot11Elt, Dot11Beacon


# NSM IMPORTS
from nsm_vars import Variables


# CONSTANTS
console = Variables.console





class DataBase():
    """This will touch database dir"""

    
    class Bluetooth():
        """Bluetooth/BLE database"""
    
        @staticmethod
        def get_manufacturer(id, data, verbose=False) -> str:
            """This will convert manuf data -> manuf"""



            try:

                path = Path(__file__).parent.parent / "database" / "bluetooth_sig" / "assigned_numbers" / "company_identifiers" / "company_ids.json"
                
                if not path.exists(): console.print("[bold red][-] Database Error: BLE path doesnt exist"); return False
                

                with open(str(path), "r") as file:
                    company_ids = json.load(file)
        

                for key, value in company_ids.items():

                    if int(key) == int(id):

                        manufacturer = value["company"]

                        if verbose: console.print(f"[bold green][+] {id} --> {manufacturer}")
                        
                        #if data: return f"{manufacturer} | {data}"
                        return manufacturer
                
                return False



            except Exception as e: console.print(f"[bold red][-] Database Exception Error:[bold yellow] {e}")



        @classmethod
        def _get_vendor(cls, mac: str, verbose=True) -> str:
            """MAC --> Vendor | lookup"""
            
            try:

                manuf_path = str(Path(__file__).parent.parent / "database" / "manuf_old.txt")

                vendor = manuf.MacParser(manuf_path).get_manuf_long(mac=mac)
                
                if verbose:
                    console.print(f"Manuf.txt pulled -> {manuf_path}")            
                    console.print(f"[bold green][+] Vendor Lookup:[/bold green] {vendor} -> {mac}")
                

                return vendor
                    
            

            except FileNotFoundError:
                console.print(f"[bold red][-] Failed to pull manuf.txt:[bold yellow] File not Found!"); exit()
        
            
            except Exception as e:
                console.print(f"[bold red][-]Exception Error:[bold yellow] {e}"); exit()
        

        @staticmethod
        def _get_vendor_new(mac: str, verbose=True) -> str:
            """MAC Prefixes --> Vendor"""
            

            try:

                manuf_path = str(Path(__file__).parent.parent / "database" / "manuf_ring_mast4r.txt")

                mac_prefix = mac.split(':'); prefix = mac_prefix[0] + mac_prefix[1] + mac_prefix[2]


                with open(manuf_path, "r") as file:

                    for line in file:
                        parts = line.strip().split('\t')
                        
                        if parts[0] == prefix:

                            vendor = parts[1]

                            if verbose: console.print(f"[bold green][+] {parts[0]} --> {vendor}" )
                            
                            return vendor


            except FileNotFoundError:
                console.print(f"[bold red][-] Failed to pull manuf.txt:[bold yellow] File not Found!"); exit()
        

            except Exception as e:
                console.print(f"[bold red][-] Exception Error:[bold yellow] {e}")
        

        @staticmethod
        def get_vendor_main(mac: str, verbose=False) -> str:
            """This will use ringmast4r and wireshark vendor database"""


            vendor = DataBase.Bluetooth._get_vendor(mac=mac, verbose=verbose) or False; c = 1

            if not vendor: vendor = DataBase.Bluetooth._get_vendor_new(mac=mac, verbose=verbose) or False; c = 2 

            return vendor
     
        

    class WiFi():
        """Wifi database"""



        @classmethod
        def _get_vendor(cls, mac: str, verbose=True) -> str:
            """MAC --> Vendor | lookup"""
            
            try:

                manuf_path = str(Path(__file__).parent.parent / "database" / "manuf_old.txt")

                vendor = manuf.MacParser(manuf_path).get_manuf_long(mac=mac)
                
                if verbose:
                    console.print(f"Manuf.txt pulled -> {manuf_path}")            
                    console.print(f"[bold green][+] Vendor Lookup:[/bold green] {vendor} -> {mac}")
                

                return vendor

            except FileNotFoundError:console.print(f"[bold red][-] Failed to pull manuf.txt:[bold yellow] File not Found!"); exit()
            except Exception as e: console.print(f"[bold red][-]Exception Error:[bold yellow] {e}"); exit()
        

        @staticmethod
        def _get_vendor_new(mac: str, verbose=True) -> str:
            """MAC Prefixes --> Vendor"""
            

            try:

                manuf_path = str(Path(__file__).parent.parent / "database" / "manuf_ring_mast4r.txt")

                mac_prefix = mac.split(':'); prefix = mac_prefix[0] + mac_prefix[1] + mac_prefix[2]


                with open(manuf_path, "r") as file:

                    for line in file:
                        parts = line.strip().split('\t')
                        
                        if parts[0] == prefix:

                            vendor = parts[1]

                            if verbose: console.print(f"[bold green][+] {parts[0]} --> {vendor}" )
                            
                            return vendor


            except FileNotFoundError: console.print(f"[bold red][-] Failed to pull manuf.txt:[bold yellow] File not Found!"); exit()
            except Exception as e: console.print(f"[bold red][-] Exception Error:[bold yellow] {e}")
        
        
        @staticmethod
        def get_vendor_main(mac: str, verbose=False) -> str:
            """This will use ringmast4r and wireshark vendor database"""


            vendor = DataBase.WiFi._get_vendor(mac=mac, verbose=verbose) or False; c = 1

            if not vendor: vendor = DataBase.WiFi._get_vendor_new(mac=mac, verbose=verbose) or False; c = 2 

            return vendor
        

        @staticmethod
        def get_host_name(target_ip):
            """This will retrieve hostname"""

            
            try:

                host = socket.gethostbyaddr(target_ip)[0].split(".")[0]
                return host
        
            except Exception as e: console.print(f"[bold red][-] Database Exception Error:[bold yellow] {e}"); return False
        

        

        # ===============
        #  WiFi pkt Parsing
        # ===============
        @staticmethod
        def get_frequency(freq):
            """This will return frequency"""

            if freq in range(2412, 2472): return "2.4 GHz"
            elif freq in range(5180, 5825): return "5 GHz"
            else: return "6 GHz"


        @staticmethod
        def get_encryption(pkt):

            if not pkt.haslayer(Dot11Beacon):return None

            cap = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}")
            if "privacy" not in cap:return "OPEN"

            rsn = pkt.getlayer(Dot11Elt, ID=48)
            wpa = pkt.getlayer(Dot11Elt, ID=221)

            if rsn:
                rsn_info = rsn.info
                if b"\x00\x0f\xac\x08" in rsn_info: return "WPA3"
                return "WPA2"

            if wpa and b"WPA" in wpa.info: return "WPA"
            return "WEP"

        
        @staticmethod
        def get_rssi(pkt, format=False):
            """This method will be responsible for pulling signal strength"""

            signal = ""
            signal = f"[bold red]Signal:[/bold red] {signal}"

            if pkt.haslayer(RadioTap):
                rssi = getattr(pkt, "dBm_AntSignal", False)

                if rssi:
                    if format: return f"{rssi} dBm"
                    return rssi


        @staticmethod
        def _frequency_to_channel(freq):

            if 2412 <= freq <= 2484:  return (freq - 2407) // 5
            elif 5180 <= freq <= 5825: return (freq - 5000) // 5
            # 6 GHz and others can be added as needed
            return None


        @staticmethod
        def get_channel(pkt):
            """This will be used to get the ssid channel"""

            elt = pkt[Dot11Elt]
            channel = 0

            while isinstance(elt, Dot11Elt):

                if elt.ID == 3: channel = elt.info[0]; return channel

                elt = elt.payload


            if pkt.haslayer(RadioTap):
                try:
                    freq = pkt[RadioTap].ChannelFrequency

                    if freq:
                        if 2412 <= freq <= 2484:   return (freq - 2407) // 5
                        elif 5180 <= freq <= 5825: return (freq - 5000) // 5
                        return None
            
                except Exception: pass
            
            return None
            



class Background_Threads:
    """This module will house background permanent running threads"""

    # CLASS VARIABLES
    hop = True
    channel = 0





    @classmethod
    def channel_hopper(cls, set_channel=False, verbose=False):
        """This method will be responsible for automatically hopping channels"""


        def hopper():

            delay = 0.25
            all_hops = [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]

            iface = Variables.iface


            # TUNE HOP
            if set_channel:
                cls.hop = False
                time.sleep(2)

                try:
                    subprocess.Popen(
                        [
                            "sudo",
                            "iw",
                            "dev",
                            iface,
                            "set",
                            "channel",
                            str(set_channel),
                        ],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                        stdin=subprocess.DEVNULL,
                        start_new_session=True,
                    )

                except Exception as e:
                    console.print(f"[bold red]Exception Error:[bold yellow] {e}")

            # AUTO HOPPING
            while cls.hop:
                for channel in all_hops:
                    try:
                        # HOP CHANNEL
                        subprocess.Popen(
                            [
                                "sudo",
                                "iw",
                                "dev",
                                iface,
                                "set",
                                "channel",
                                str(channel),
                            ],
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            stdin=subprocess.DEVNULL,
                            start_new_session=True,
                        )
                        cls.channel = channel
                        if verbose:
                            console.print(
                                f"[bold green]Hopping on Channel:[bold yellow] {channel}"
                            )

                        # DELAY
                        time.sleep(delay)

                    except Exception as e:
                        console.print(f"[bold red]Exception Error:[bold yellow] {e}")

        threading.Thread(target=hopper, args=(), daemon=True).start()
        cls.hop = True

    @staticmethod
    def change_iface_mode(iface, mode=["managed", "monitor"], verbose=True):
        """This method will be resposnible for chaning iface mode"""

        # if mode == "monitor": return
        try:
            if mode == "monitor" or mode == 2:
                # os.system(f"sudo ip link set {iface} down; sudo iw dev {iface} type monitor; sudo ip link set {iface} up")

                subprocess.run(
                    ["sudo", "ip", "link", "set", f"{iface}", "down"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                subprocess.run(
                    ["sudo", "iw", "dev", f"{iface}", "set", "type", "monitor"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                subprocess.run(
                    ["sudo", "ip", "link", "set", f"{iface}", "up"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

            elif mode == "managed" or mode == 1:
                subprocess.run(
                    ["sudo", "ip", "link", "set", f"{iface}", "down"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                subprocess.run(
                    ["sudo", "iw", "dev", f"{iface}", "set", "type", "managed"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                subprocess.run(
                    ["sudo", "ip", "link", "set", f"{iface}", "up"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )

            else:
                console.print(
                    "[bold red][-] non-valid choice picked for change_iface_mode!"
                )
                return False

            check = subprocess.run(
                ["iw", "dev", f"{iface}", "info"], capture_output=True, text=True
            )
            if (
                "type monitor" in check.stdout.lower()
                or "type managed" in check.stdout.lower()
            ):
                console.print(
                    f"[bold green][+] Successfully changed iface_mode --> {mode}!"
                )

        except Exception as e:
            console.print(e)

        finally:
            console.print("[bold red] Ctrl + c x2 == EXIT\n")





class Extensions():
    """This will run extneded codes"""

    
    server_ip   = False
    alpha       = 0.05
    avg         = None
    last_count  = 0
    last_color  = False
    drive_error = False


    @classmethod
    def _average_ratio(cls, current_count):
        """This will track average device count over time"""


        if cls.avg is None: cls.avg = float(current_count); return 0.0
        cls.avg = (cls.avg * (1 - cls.alpha)) + (current_count * cls.alpha)

        if cls.avg == 0: return 0.0
        score = (current_count - cls.avg) / cls.avg

        return round(score, 3)

        

    @classmethod
    def _change_color(cls, current_count, average_ratio, server_ip, timeout=3):
        """This will send push a http --> ESP32"""


        """
        Green   → Safe
        Yellow  → Caution
        Orange  → Warning
        Red     → Danger
        Purple  → Abnormal / Emergency

        Baseline = “what's normal here”

        Ratio = “how weird is right now”

        Small bumps → Yellow

        Big jumps → Orange / Red

        Massive jumps → Purple

        """


        if average_ratio <= 0.0:    color = "green"
        elif average_ratio <= 0.25: color = "yellow"
        elif average_ratio <= 0.6:  color = "orange"
        elif average_ratio <= 1.0:  color = "red"
        else:                       color = "purple"
        
        
        if server_ip:
            try:

                url = f"http://{server_ip}/?color={color}"
                response = requests.post(url=url, timeout=timeout)

                if response.status_code in [200,204]: 
                    console.print(f"[bold green][+] Successfully pushed:[/bold green] {color} --> {server_ip}  <-->  {url}")
                
                else: console.print(f"[bold red][-] Failed to push to LED Server:[bold yellow] Status code: {response.status_code}")
            
            except Exception as e: console.print(f"[bold red]Exception Error:[bold yellow] {e}")

        
        data = [current_count, average_ratio, color]
        return data
        



    @classmethod
    def _tts_google(cls, data=False, verbose=True):
        """This will be responsible for pushing sound to --> Yoda Audio player"""


        current_count = data[0]
        average_ratio = data[1]
        color         = data[2]
        percent       = abs(average_ratio * 100)

        valid = ["green", "yellow", "orange", "red", "purple"]
        
        if cls.last_count < current_count:
            say = f"[bold green][UP] ATTENTION, the amount of devices in your area has increased from {cls.last_count} to {current_count}. up {percent} percent!"

        elif cls.last_count > current_count:
            say = f"[bold red][DOWN] ATTENTION, the amount of devices in your area has decreased from {cls.last_count} to {current_count}. down {percent} percent!"

        else: return


        if color in valid and cls.last_count != current_count:

            if verbose: console.print(say)
            #console.print(f"{cls.last_color} --> {color}")
            #console.print(f"{cls.last_count} --> {current_count}")

        


    @classmethod
    def Controller(cls, current_count: int, server_ip: str):
        """This one method will be responbile for calling and handling all methods within this class <--"""

        

        average = cls._average_ratio(current_count=current_count)
        data    = cls._change_color(current_count=current_count, average_ratio=average, server_ip=server_ip)

        cls._tts_google(data=data)

        cls.last_count = data[0]
        cls.last_color = data[2]

    @classmethod
    def get_status(cls):
        """Return current threat status for web API"""
        return {
            "current_count": cls.last_count,
            "baseline": round(cls.avg, 2) if cls.avg is not None else 0,
            "color": cls.last_color or "green",
            "percent": round(abs(((cls.last_count - (cls.avg or 0)) / (cls.avg or 1)) * 100), 1) if cls.avg else 0
        }

