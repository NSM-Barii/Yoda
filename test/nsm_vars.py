# THIS WILL HOUSE MULTI-MODULE VARS (post yoda-jr)


# IMPORTS
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from mcp.server.fastmcp import FastMCP
import threading, queue, time




# MONITOR METHODS
"""
monitor_bluetooth
monitor_deauth
monitor_evil_twin
monitor_ssid_count



"""

# Kodak: https://www.youtube.com/watch?v=accWa7GGCd4&list



class Variables():
    """This will house multi module vars"""



    EVENT_TIMES = {}
    EVENT_QUEUE = queue.Queue()
    LAST_EVENT_TIME = 0
    EVENT_COOLDOWN = 5


    @classmethod
    def push_event(cls, text):
        """Text -> TTS"""


        now = time.time()

        last = cls.EVENT_TIMES.get(text, 0)

        if now - last < cls.EVENT_COOLDOWN: return

        cls.EVENT_TIMES[text] = now
        cls.EVENT_QUEUE.put(text)


    

    # CONSTANTS
    console = Console()
    mcp  = FastMCP("Yoda")
    LOCK = threading.RLock()


    # RICH VARS
    panel = Panel(renderable="Developed by NSM Barii", style="bold yellow", border_style="bold red", expand=False)
    table = Table(title="Developed by NSM Barii", style="bold purple", border_style="bold red", title_style="bold purple", header_style="bold purple")
    refresh_per_second = 1
    

    
    iface     = "wlan1"  # FOR MONITOR MODE
    subnet    = "192.168.1.0/24"
    ip_router = "192.168.1.1"
    ip_local  = None
    verbose   = False

    




    @classmethod
    def Attacks(cls):
        """This will house all the different attacks of which we are going to do"""

            
        # =============================
        # WiFI/BLE BACKGROUND SCANNING
        # =============================
        global_ble_devices  = 0
        global_ssids         = 0

        
        
        # ================================
        # WiFi  //   MONITOR MODE ATTACKS
        # ================================


        # DEFAULT
        timeout = 15
        channel = 6 # OR 6

        # WAR DRIVING
        mode = 1 # AP's ONLY == 1 else 2 == FOR CLIENTS AND NON BEACON FRAMES

        # EVIL TWIN // BEACON FLOOOOD
        portal_num = 1    

        # DEAUTH // CLIENT SNIFFER
        mac_src    = None
        mac_dst    = None
        mac_client = None  # SINGLE CLIENT DEAUTH

        inter    = None
        loop     = None
        count    = None
        realtime = None

        reasons = [4,5,7,15]



        # ===============
        #  Bluetooth/BLE
        # ===============


        live_map  = {}
        war_drive = {}
        unstable_devices = 0
        server_ip = False

