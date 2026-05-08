# THIS METHOD WILL BE RESPONSIBLE FOR IMPORTING SHIT VIA DATABASE DIR



# IMPORTS
import json, socket, manuf, requests, subprocess, threading, time, random, sqlite3
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
        
        
        # ============
        # LAN PARSING
        # ============
        @staticmethod
        def get_conn_status(verbose=True):
            """This method will be a blocking method for if the user is online or not"""


            domains = ["google.com", "cloudflare.com", "github.com", "wikipedia.org", ]


            try:

                host = socket.gethostbyname(random.choice(domains))

                if host:
                    
                    if verbose:
                        console.print(f"[bold blue]Connection Status:[bold green] ONLINE")
                    
                    return True
                
                
                console.print(f"[bold blue]Connection Status:[bold red] OFFLINE")
                return False
            


            except Exception as e:

                if verbose:
                    console.print(f"[bold red]Exception Error:[bold yellow] {e}")
                    console.print(f"[bold blue]Connection Status:[bold red] OFFLINE")


                return False


        @staticmethod
        def establish_reconnection(verbose=False):
            """This method will be called upon if there is a connection interruption"""


            # CHECK DELAY
            delay = False


            while True:
                
                if delay:
                    time.sleep(delay)

                try:

                    status = Connection_Handler.get_conn_status(verbose=False)


                    if status:

                        console.print(f"Connection Status back online  -  Resuming program!", style="bold green")

                        
                        # RESUME PROGRAM
                        return True
                    

                    else:
                        
                        if verbose:
                            console.print(f"Connection status still offline", style="bold red")

                        delay = 3
                

                except Exception as e:

                    if verbose:
                        console.print(f"Connection status still offline  -  {e}", style="bold red")

                    delay = 3

        
        @classmethod
        def status_checker(cls, target_ip, target_mac, host, vendor, iface):
            """This method will be responsible for monitroing the connection status of the target_ip"""


            
  
            # LEGACY CONTROLLER
            leg = False


            # VARS
            verbose = False
            RESET = 0.5
            delay = 0.5
            timeout = 0.5
            online = 0
            count = 0
            
            # COUNT THE AMOUNT OF SCANS PERFORMED
            scans = 0


            # COLORS
            c1 = "bold red"
            c2 = "bold blue"
            c3 = "bold purple"
            c4 = "bold yellow"


            # GET LOCAL
            local_ip = File_Handling.get_json(verbose=False)["local_ip"]


            # PACKETS
            arp = Ether(dst=target_mac) / ARP(pdst=target_ip)
            ping = IP(dst=target_ip) / ICMP()


            while True:

                
                try:

                    # APPEND
                    count += 1

                    # GET
                    with LOCK:
                        response = srp(arp, iface=iface, timeout=timeout, verbose=0)[0]
                        
                        # DOUBLE CHECK
                        if not response:
                            pass
                        # console.print("2")
                            #response = sr1(ping, iface=iface, timeout=timeout, verbose=0)


                    # IF NOW ONLINE
                    if response and not online:
                        
                        # UPDATE
                        online = True
                        delay = RESET
                        timeout = RESET
                        count = 0


                        if verbose:
                            console.print(f"[{c1}][+][/{c1}] Node Online: [{c4}]{target_ip} ")


                        
                        # NEW WAY
                        cls.nodes[target_ip] = {
                            "target_ip": target_ip,
                            "target_mac": target_mac,
                            "host": host,
                            "vendor": vendor,
                            "status": "online"
                        }

                        # UPDATE STATUS
                        status = "online"

                        # ANNOUNCE
                        if scans > 3:
                            Utilities.announce_device(ip=target_ip, host=host, vendor=vendor, type=2, status=status)


                        # PUSH STATUS
                        if leg:
                            with LOCK:
                                Push_Network_Status.push_device_info(
                                    
                                    target_ip=target_ip,
                                    target_mac=target_mac,
                                    host=host,
                                    vendor=vendor,
                                    status="online"
                                    
                                    )
                        
                        
                        # DELAY
                        delay = RESET   
                        timeout = RESET
                        time.sleep(delay)
                    

                    # STILL ONLINE
                    elif response:

                        if verbose:
                            console.print(f"[{c1}][+][/{c1}] Node Online still: [{c4}]{target_ip} ")


                        # DELAY
                        time.sleep(delay)


                        # TRY AND RE QUERY VENDOR IF NONE
                        if not vendor:
                            vendor = Utilities.get_vendor(mac=target_mac)
                            cls.nodes[target_ip] = {
                                "target_ip": target_ip,
                                "target_mac": target_mac,
                                "host": host,
                                "vendor": vendor,
                                "status": "online"
                            }


                            #console.print("got --> ", vendor)
                        

                    

                    # NOW OFFLINE
                    elif count > 6:


                        # NEW WAY
                        cls.nodes[target_ip] = {
                            "target_ip": target_ip,
                            "target_mac": target_mac,
                            "host": host,
                            "vendor": vendor,
                            "status": "offline"
                        }
                        

                        # UPDATE STATUS
                        status = "offline"


                        #console.print(response)
                        


                        # ANNOUNCE
                        if online:
                            Utilities.announce_device(ip=target_ip, host=host, vendor=vendor, type=2, status=status)

                        # PUSH STATUS
                        if leg:
                            with LOCK:
                                Push_Network_Status.push_device_info(
                                    
                                    target_ip=target_ip,
                                    target_mac=target_mac,
                                    host=host,
                                    vendor=vendor,
                                    status="offline"
                                    
                                    )
                        

                        # OFFLINE
                        online = False
                        

                        # DELAY
                        delay = RESET   
                        timeout = RESET
                        time.sleep(delay)
                    

                    
                    # RE-TRY ARP
                    else:

                        count += 1
                        delay += 0.5
                        timeout += 0.5 if timeout < 2.5 else 2.5
                        delay += 0.5 if delay < 2.5 else 2.5
                    

                        time.sleep(delay)


                        if verbose:
                            console.print("arping -- ", target_ip)
                    

                    # FOR TESTING
                    if verbose:
                        console.print("here -- ", target_ip)
                    scans += 1
                

                except Exception as e:
                        console.print(e)


                        # REMOVE FROM LIST
                        from nsm_network_scanner import Network_Scanner
                        Network_Scanner.subnet_devices.remove(target_ip)


                        # NEW WAY
                        cls.nodes[target_ip] = {
                            "target_ip": target_ip,
                            "target_mac": target_mac,
                            "host": host,
                            "vendor": vendor,
                            "status": "offline"
                        }


                        # UPDATE STATUS
                        status = "offline"


                        # ANNOUNCE
                        Utilities.announce_device(ip=target_ip, host=host, vendor=vendor, type=2, status=status)


                        # SET OFFLINE (FOR NOW)
                        if leg:
                            with LOCK:
                                Push_Network_Status.push_device_info(
                                    
                                    target_ip=target_ip,
                                    target_mac=target_mac,
                                    host=host,
                                    vendor=vendor,
                                    status="offline"
                                    
                                    )


                        # KILL THREAD
                        console.print(f"[bold red][-] Thread Killed:[bold yellow] {target_ip}")

                        break




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

            iface = Variables.iface_monitor


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

        cls.hop = True
        threading.Thread(target=hopper, args=(), daemon=True).start()

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


class DeviceLog():
    """Persistent SQLite log of all seen devices across sessions."""

    DB_PATH = Path(__file__).parent / "devices.db"

    @classmethod
    def _conn(cls):
        return sqlite3.connect(cls.DB_PATH)

    @classmethod
    def init(cls):
        with cls._conn() as c:
            c.execute("""
                CREATE TABLE IF NOT EXISTS ble_devices (
                    mac          TEXT PRIMARY KEY,
                    name         TEXT,
                    vendor       TEXT,
                    manufacturer TEXT,
                    first_seen   TEXT,
                    last_seen    TEXT,
                    times_seen   INTEGER DEFAULT 1
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS wifi_aps (
                    bssid      TEXT PRIMARY KEY,
                    ssid       TEXT,
                    vendor     TEXT,
                    channel    TEXT,
                    first_seen TEXT,
                    last_seen  TEXT,
                    times_seen INTEGER DEFAULT 1
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS wifi_clients (
                    mac        TEXT PRIMARY KEY,
                    vendor     TEXT,
                    ap_bssid   TEXT,
                    first_seen TEXT,
                    last_seen  TEXT,
                    times_seen INTEGER DEFAULT 1
                )
            """)

    @classmethod
    def log_ble(cls, mac, name, vendor, manufacturer) -> bool:
        """Returns True if brand new device, False if seen before."""
        from datetime import datetime
        now = datetime.now().isoformat(timespec="seconds")
        with cls._conn() as c:
            row = c.execute("SELECT times_seen FROM ble_devices WHERE mac=?", (mac,)).fetchone()
            if row:
                c.execute("UPDATE ble_devices SET last_seen=?, times_seen=times_seen+1 WHERE mac=?", (now, mac))
                return False
            c.execute("INSERT INTO ble_devices VALUES (?,?,?,?,?,?,1)", (mac, name, vendor, manufacturer, now, now))
            return True

    @classmethod
    def log_ap(cls, bssid, ssid, vendor, channel) -> bool:
        """Returns True if brand new AP, False if seen before."""
        from datetime import datetime
        now = datetime.now().isoformat(timespec="seconds")
        with cls._conn() as c:
            row = c.execute("SELECT times_seen FROM wifi_aps WHERE bssid=?", (bssid,)).fetchone()
            if row:
                c.execute("UPDATE wifi_aps SET last_seen=?, times_seen=times_seen+1 WHERE bssid=?", (now, bssid))
                return False
            c.execute("INSERT INTO wifi_aps VALUES (?,?,?,?,?,?,1)", (bssid, ssid, vendor, channel, now, now))
            return True

    @classmethod
    def log_client(cls, mac, vendor, ap_bssid) -> bool:
        """Returns True if brand new client, False if seen before."""
        from datetime import datetime
        now = datetime.now().isoformat(timespec="seconds")
        with cls._conn() as c:
            row = c.execute("SELECT times_seen FROM wifi_clients WHERE mac=?", (mac,)).fetchone()
            if row:
                c.execute("UPDATE wifi_clients SET last_seen=?, times_seen=times_seen+1 WHERE mac=?", (now, mac))
                return False
            c.execute("INSERT INTO wifi_clients VALUES (?,?,?,?,?,1)", (mac, vendor, ap_bssid, now, now))
            return True


