# THIS MODULE WILL HOUSE MONITORING CLASSESS FOR WiFi/Bluetooth/Evil_Twins/etc



# UI IMPORTS
from rich.table import Table


# NETWORK IMPORTS
from bleak import BleakClient, BleakScanner
from scapy.all import sniff, RadioTap
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11AssoReq, Dot11ProbeReq, Dot11Elt, Dot11Deauth


# ETC IMPORTS
import asyncio, time, subprocess, time
from datetime import datetime


# NSM IMPORTS
from nsm_vars import Variables
from nsm_database import DataBase, Extensions, Background_Threads


# CONSTANTS
console = Variables.console
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
    
    

    @staticmethod
    def _get_manuf(manuf):
        """This will parse and get manuf"""


    
        if not manuf: return False

        for key, value in manuf.items():
            id = key; hex = value.hex()
        


        company = DataBase.get_manufacturer(id=id, data=hex)


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
        timeout = 10

        table = Table(title="BLE Driving", title_style="bold red", border_style="bold purple", style="bold purple", header_style="bold red")
        table.add_column("#"); table.add_column("RSSI", style=c2); table.add_column("Mac", style=c3); table.add_column("Manufacturer", style=c5); table.add_column("Local_name"); table.add_column("UUID", style=c3)


        try:

            scanner = BleakScanner()

            while True:

                await scanner.start()
                await asyncio.sleep(5)
                await scanner.stop()
                devices = scanner.discovered_devices_and_advertisement_data



                if devices: 
                
                    
                    for mac, (device, adv) in devices.items():
                        
                        name  = adv.local_name or False
                        rssi  = adv.rssi
                        uuid  = adv.service_uuids or False
                        manuf = cls._get_manuf(manuf=adv.manufacturer_data) 
                        vendor = cls.DataBase.get_vendor_main(mac=mac, verbose=False) 
                        up_time = time.time()
                                        

                        data = {
                            "rssi": rssi,
                            "addr": mac,
                            "manuf": manuf,
                            "vendor": vendor,
                            "name": name,
                            "uuid": uuid,
                            "up_time": up_time
                        }
   

                        cls.live_map[mac] = data
         

                        if mac not in cls.devices:
                            
                            cls.devices.append(mac)
                            cls.war_drive[len(cls.devices)] = data
            
                            console.print(f"{len(cls.devices)}", rssi, mac, manuf, vendor, name, uuid)
        

                

                # WILL MAKE A GLOBALIZED SAVE FOR ALL INFO FROM ALL MONITOR METHODS
                #DataBase.push_results(devices=cls.war_drive, verbose=False)


                count = len(devices)
                Extensions.Controller(current_count=count, server_ip=server_ip)


                        

            console.print(f"\n[bold green][+] Found a total of:[bold yellow] {len(cls.devices)} devices")


        except KeyboardInterrupt:  return KeyboardInterrupt
        except Exception as e:     return Exception


        
    @classmethod
    def main(cls):
        """Run from here"""
        

        cls.devices = []
        cls.num = 0

        server_ip   = Variables.server_ip
        cls.live_map    = Variables.live_map
        cls.war_drive   = Variables.war_drive


        try: 
            
            console.print("[yellow][+] Bluetooth/BLE Monitoring Active")
            asyncio.run(Monitor_Bluetooth._ble_printer(server_ip=server_ip))
    
        except KeyboardInterrupt: console.print("\n[bold red]Stopping....")
        except Exception as e: console.print(f"[bold red]Sniffer Exception Error:[bold yellow] {e}")



class Monitor_Deauth_python():
    """This class will be responsible for grabbing surrounding layer 2 traffic <-- snatch"""

    DataBase = DataBase.WiFi


 
    @classmethod
    def _sniffer(cls, iface, timeout=5, verbose=False):
        """This will sniff frames out the air"""

        loops = 0

        console.print(f"[bold green][*] Launching Sniffer Daemon[/bold green] - Mode: {cls.mode}")


        while cls.sniff:

            try:

                loops += 1
                if verbose: console.print(f"[bold yellow]Loop: {loops}")

                sniff(iface=iface, timeout=timeout, store=0, prn=cls._parser); time.sleep(1)


            except KeyboardInterrupt as e: console.print(f"[bold yellow][-] Byeeeeee......."); cls.sniff = False


            except Exception as e: console.print(f"[bold red][-] Exception Error:[bold yellow] {e}"); cls.sniff = False
        


        console.print(f"[bold red][-] SNIFFER Terminated! - Threads: {cls.thread_count}")
    


    @classmethod
    def _parser(cls, pkt):
        """This method will be resposible for parsing said packets that are recieved from _sniffer <-- pass argument"""
        

        def parser(pkt):
            

            c1 = "bold green"
            c2 = "bold blue"
            c3 = "bold yellow"
            c4 = "bold red"

            go = False
            ssid = False

            # ADDR1 == DST
            # ADDR2 == SRC
            # ADDR3 == SRC
            
            if not cls.sniff: return


            if pkt.haslayer(Dot11Deauth) and cls.mode == 1:

                #console.print(pkt)


                try:


                    addr1 = pkt[Dot11].addr1 
                    addr2 = pkt[Dot11].addr2 

                    channel  = False
                    
                    cls.deauths[addr2]["deauths"] += 1
                    console.print(cls.deauths)
                    cls.deauths[addr2]["dst"] = {"src": addr2, 
                                                 "dst": addr1}
                    console.print(f"[{c4}][*] Deauth Attack detected[/{c4}] - Src: {addr2}  Dst: {addr1} - Channel: {channel}")
                    console.print(cls.deauths)


                except Exception as e: console.print(f"[bold red][-] Exception Error:[bold yellow] {e   }")


            elif pkt.haslayer(Dot11Beacon) and cls.mode == 2:


                try:
                    addr1 = pkt[Dot11].addr1 if pkt[Dot11].addr1 != "ff:ff:ff:ff:ff:ff" else False
                    addr2 = pkt[Dot11].addr2 if pkt[Dot11].addr2 != "ff:ff:ff:ff:ff:ff" else False

                    ssid        = pkt[Dot11Elt].info.decode(errors="ignore") or "Hidden SSID"
                    vendor      = cls.DataBase.get_vendor_main(mac=addr2)
                    rssi        = cls.DataBase.get_rssi(pkt=pkt, format=False)
                    channel     = cls.DataBase.get_channel(pkt=pkt)
                    encryption  = cls.DataBase.get_encryption(pkt=pkt)
                    frequency   = cls.DataBase.get_frequency(freq=pkt[RadioTap].ChannelFrequency)



                    if cls.hide:
                        t = [s for s in ssid]
                        if len(t) > 4: 
                            ssid = (f"{t[0]}{t[1]}{t[2]}{t[3]}")
                

                except Exception as e: console.print(f"[bold red][-] Parse Error:[bold yelow] {e}"); cls.sniff = False  
                

                try:
                    
                    if not any(stored_ssid == ssid for stored_ssid, _ in cls.ssids):
                        cls.master[ssid] = {
                            "rssi": rssi,
                            "mac": addr2,
                            "encryption": encryption,
                            "frequency": frequency,
                            "channel": channel,
                            "vendor": vendor,
                            "traffic": 0,
                            "clients": []
                        }

                        cls.ssids.append((ssid, addr2))
                        console.print(f"[bold green][+] SSID:[bold yellow] {ssid} --> {addr2}")
                    
                except Exception as e: console.print(f"[bold red][-] Beacon Error: {e}"); cls.sniff = False



            elif pkt.haslayer(Dot11) and pkt.type == 2 and cls.mode == 2: 


                addr1 = pkt[Dot11].addr1 if pkt[Dot11].addr1 != "ff:ff:ff:ff:ff:ff" else False
                addr2 = pkt[Dot11].addr2 if pkt[Dot11].addr2 != "ff:ff:ff:ff:ff:ff" else False


                for id, id_mac in cls.ssids:
                    
                    if id_mac == addr2 or id_mac == addr1: go = True; ssid = id
                    #print(id, id_mac, go)

                    if go:
                        cls.master[id]["traffic"] +=1

            
                if not go: return
            

                vendor  = cls.DataBase.get_vendor_main(mac=addr1 or addr2)
                channel = cls.DataBase.get_channel(pkt=pkt)
                #console.print(vendor, channel)
                
          
                try:

                    if addr1 not in cls.macs and addr1 and ssid:
                        console.print("heyyy")
                            
                        data = (
                            addr1,
                            channel,
                            vendor,
                        )
                        
                        cls.master[ssid]["clients"].append(data)
                        cls.macs.append(addr1)


                        console.print(f"[bold green][+] addr1: {addr1} -> ")
                    

                    
                    if addr2 not in cls.macs and addr2 and ssid:
                        
                        data = (
                            addr2,
                            channel,
                            vendor,
                        )
                        
                        cls.master[ssid]["clients"].append(data)
                        cls.macs.append(addr2)


                        console.print(f"[bold green][+] addr2: {addr2} -> ")
                    
                        #console.print(cls.master)
                

                except Exception as e: console.print(f"[bold red][-] GO Error: {e}"); cls.sniff = False

 
        if not cls.sniff: return Exception 
        #print(pkt)
        #cls.executor.submit(parser, pkt); cls.thread_count += 1
        #parser(pkt=pkt)

                
    
    @classmethod
                
    def main(cls):
        """This will run class wide logic"""


        # VARS


        cls.hide = False
        cls.thread_count = 0
        cls.sniff = True
        cls.deauths = {}
        cls.master = {}
        cls.macs = []
        cls.ssids = []
        
        iface    = Variables.iface
        cls.mode = 1


        Background_Threads.channel_hopper()
        cls._sniffer(iface=iface)
        #threading.Thread(target=WiFi_Snatcher._sniffer, args=(iface, ), daemon=True).start()


# WRAPPER OFF TSHARK
class Monitor_Deauth_Tshark():
    """This will be used to monitor for deauth attacks"""


    @classmethod
    def _sniffer(cls, iface):
        """This will be used to sniff for deauth frames"""


        count = 0
        total = 0
        last_deauth = time.time()
        start_time  = time.time()



        cmd = [
            "tshark",
            "-i", iface,
            "-l", 
            "-T", "fields",
            "-e", "frame.number",
            "-e", "frame.time_epoch",
            "-e", "wlan.sa",
            "-e", "wlan.da",
            "-e", "wlan.fc.type_subtype",
            "-Y", "wlan.fc.type_subtype == 0x0c"

        ]


        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True
            
        )


         

        """
        The process variable creates a live session which deauht packets when there detected meaning its a loop in it of itself.
        The conditions only run if a line is printed from the process variable
        """
        c1 = "bold red"
        c2 = "bold green"
        c3 = "bold yellow"
        
        for line in process.stdout:

            count += 1
            space  = "     "
            now = time.time()
            src = False; dst = False
            


            if now - start_time >= 1:

                if (count >= 1) and (last_deauth is not None): 
                   
                    parts = line.strip().split("\t")
                    
                    ['20', '1776444991.614093311', '72:35:3d:f8:c7:43', 'ff:ff:ff:ff:ff:ff', '0x000c']

                    if len(parts) >= 3:
                        src = parts[2]
                        dst = parts[3]
                        subtype = parts[4]

                    timestamp = datetime.now().strftime("%m/%d/%Y, %H:%M:%S"); last_deauth = now


                    console.print(f"[bold red][!] Deauth ATTACK Detected![/bold red]"
                                f"\n{space}[{c3}]Time:[/{c3}] {timestamp}"
                                f"\n{space}[{c3}]Rate:[/{c3}] {count}"
                                f"\n{space}[{c3}]Src:[/{c3}] {src} -> {dst}\n"
                                )


                
                total += count; count = 0
                start_time = now
            
            

            # THIS WILL NOT WORK
            if (last_deauth is not None) and (now - last_deauth >= 5):
                
                console.print(now - last_deauth)
            
                console.print(f"\n[bold green][+] Deauth Attack ended! Total Deauth packets sniffed: {total}")
                last_deauth = None


    
    @classmethod
    def main(cls):
        """This will run class wide logic"""


        iface = Variables.iface
        
        console.print("[yellow][+] Deauth Monitoring Active")
        cls._sniffer(iface=iface)



# tshark -i wlan1 -l -Y "wlan.fc.type_subtype == 0x0c"


# FOR MODULAR TESTING ONLY
if __name__ == "__main__":

    Monitor_Deauth_Tshark.main()
    Monitor_Bluetooth.main()