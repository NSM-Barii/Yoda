# THIS WILL BE FOR WiFi LOGIC



# NETWORK IMPORTS 
from scapy.all import sendp, sniff, ARP, Ether, srp, RadioTap
from scapy.layers.dot11 import Dot11Deauth, Dot11Elt, Dot11Beacon, Dot11
import socket, ipaddress, time, subprocess, threading


# ETC IMPORTS


# NSM IMPORTS
from vars import Variables
from database import DataBase


# CONSTANTS
#mcp    =  Variables.mcp
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


                host = DataBase.WiFi.get_host_name(target_ip=target_ip)
                vendor = DataBase.WiFi.get_vendor_main(mac=target_mac)

                devices[num] = {
                    "target_ip": target_ip,
                    "target_mac": target_mac,
                    "host": host,
                    "vendor": vendor
                }; num += 1

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

    
    
