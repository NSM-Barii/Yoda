# THIS WILL BE FOR WiFi LOGIC


# IMPORTS
from scapy.all import sendp, sniff, ARP, Ether, srp, RadioTap
from scapy.layers.dot11 import Dot11Deauth, Dot11Elt, Dot11Beacon, Dot11
import socket, ipaddress, time, subprocess, threading


# NSM IMPORTS
from vars import Variables
from database import DataBase


# CONSTANTS
console = Variables.console
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
    def scan_arp(iface=False, subnet="192.168.1.0/24"):
        """This will perform an ARP scan and from said ARP scan return found devices and associated data
        ipaddress, hostname, mac, vendor, 
        """


        c1 = "bold red"
        c2 = "bold green"
        c3 = "bold yellow"
        devices = []


        try:

            arp = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=str(subnet))


            response = srp(arp, iface=iface, timeout=5, verbose=0)[0]
        


            for sent, recv in response:

                target_ip = recv.psrc
                target_mac = recv.hwsrc


                host = DataBase.get_host(target_ip=target_ip)
                vendor = DataBase(mac=target_mac)


                d = (target_ip, target_mac, host, vendor)
                devices.append(d)

                console.print(f"{target_ip} <-> {target_mac} | {host} - {vendor}")
            

            return devices
    

        except Exception as e: console.print(f"[bold red]Exception Error:[bold yellow] {e}"); return False
    
    

    # ==============
    #  MONITOR MODE
    # ==============
    @classmethod
    def sniff_for_ssids(cls, iface, timeout=15):
        """This will scan for all the ssids in the area and return said ssids along with there info
        ssid, bssid(mac), rssi, encryption, channel, frequency
        """

        tempt = 0

        try:

            while True:
      
                time.sleep(1); tempt += 1; console.print(f"Sniff Attempt #{tempt}", style="bold green")

                sniff(iface=iface, prn=WiFi._packet_parser, count=0, store=0,timeout=3) 

                if cls.ssids: sniff(iface=iface, prn=WiFi._packet_parser, count=0, store=0, timeout=timeout); break

        except Exception as e: console.print(f"[bold red]\n\nException Error:[yellow] {e}"); return False

    
    
    # =========
    #
    # ==========


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
        def _choose_ssid_type(cls):
            """This metod will allow the user to choose the type of ssid list to advertise"""


            console.print(
                "1. ssids_trollings",
                "\n2. ssids_christmas",
                "\n3. Enter Custom list"
            )


            while True:

                try:

                    choice = console.input("\n\n[bold blue]Enter ssid type: ").strip()

                    if choice ==   "1": return   cls.trolling_ssids
                    elif choice == "2": return cls.christmas_ssids
                    elif choice == "3":

                        console.print("[bold green]Enter ssids seperated by a comma ','  Press enter when your done!")


                        raw = console.input("\n\n[bold yellow]Enter custom ssids: ").strip(); ssids = []
                        clean = (raw.split(',')) 
                        for c in clean: ssids.append(c) if c != "," else ''
                        return ssids
                    
                    else: console.print("Choose a valid option goofy")
                

                except Exception as e:
                    console.print(f"[bold red]Exception Error:[bold yellow] {e}"); input()
            

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


            elif type == 2:
                return "02:%02x:%02x:%02x:%02x:%02x" % tuple(random.randint(0, 255) for _ in range(5))


            pass


        
        @classmethod
        def get_frames(cls, amount, ssid_type, bssid_type, client="ff:ff:ff:ff:ff:ff"):
            """This method will create the frame"""


            # VAR
            frames = []
            verbose = True
            print("\n\n")

            b =  Beacon_Flooder() 
            
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

                    # CRAFT FRAME
                    frame = (
                        RadioTap() /
                        Dot11(type=0, subtype=8, addr1='ff:ff:ff:ff:ff:ff', addr2=bssid, addr3=bssid, SC=(seq << 4)) /
                        Dot11Beacon() /
                        Dot11Elt(ID='SSID', info=ssid, len=len(ssid))
                    )

                    # APPEND AND GO
                    frames.append(frame)
                    seq = (seq + 1) % 4096  # Sequence wraps at 4096


                    if verbose:
                        console.print(f"[bold red]Frame Creation --> [bold yellow]{frame}")

                print('\n')
                return frames


                    

            
            # NOW RETURN THE LIST OF FRAMES
            return frames
        
    

        @classmethod
        def frame_injector(cls, frames, count=1):
            """This method will inject the frames into the network"""


            # VARS
            sent = 0
            down = 5
            c1 = "bold red"

            # PANEL
            panel = Panel(renderable=f"Launching Attack in {down}" , title="Attack Status", style="bold yellow", border_style="bold red", expand=False)


            # LOOP
            with Live(panel, console=console, refresh_per_second=4):


                # COUNT DOWN
                while down != 0:
                    

                    # PANEL
                    panel.renderable = f"Launching Attack in {down}"
                    time.sleep(1)

                    
                    # DECREASE 
                    down -= 1

                
                # LOOP FOR ERRORS
                while True:

                    try:

                        

                        sendp(frames, verbose=0, iface=cls.iface);  sent += count * len(frames)


                        panel.renderable = (
                            f"[{c1}]Targets:[/{c1}] {len(frames)}  -  " 
                            f"[{c1}]Frames Sent:[/{c1}] {sent}  -  " 
                            )
                        

                        time.sleep(0.1)
                        


                    
                    # THIS LOGIC IS TO SUBSIDIZE SENDP
                    except KeyboardInterrupt as e:
                        console.print(f"ATTEMPTING TO ESCAPE THE MATRIX", style="bold red")

                        try:
                            time.sleep(0.5)

                            break
                        

                        except KeyboardInterrupt as e:
                            console.print("STOP PRESSING CTRL + C", style="bold yellow")


                    
                    # GENERAL ERRORS
                    except Exception as e:
                        console.print(e)
                        

                        # FOR CONSISTENT ERRORS
                        if down < 3:
                            down += 1
                        
                        elif down == 4:
                            console.print("[bold red]MAX ERRORS OCCURED: 4")
                            time.sleep(2)
                            break


        @classmethod
        def main(cls):
            """This is where class wide logic will be performed from"""

            
            # CATCH
            try:

                # GET IFACE3
                cls.iface = Frame_Snatcher.get_interface()


                # OUTPUT UI
                Frame_Snatcher.welcome_ui(iface=cls.iface, text="    WiFi \nSpoofing", skip=True)
                Background_Threads.change_iface_mode(iface=cls.iface, mode="monitor")



                # SET CHANNEL
                Background_Threads.channel_hopper(set_channel=int(6)); time.sleep(0.2)


                ssid_type = Beacon_Flooder._choose_ssid_type()

        
                # CRAFT FRAMES
                frames = Beacon_Flooder.get_frames(ssid_type=ssid_type, bssid_type=1, amount=15)

                
                # INJECT THE FRAMES
                Beacon_Flooder.frame_injector(frames=frames)


                console.print(frames)


            except KeyboardInterrupt as e:

                console.print(e) 
        

            except Exception as e:
                
                console.print(f"[bold red]Exception Error:[yellow] {e}")