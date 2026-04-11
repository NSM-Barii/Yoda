# THIS WILL HOUSE MULTI-MODULE VARS (post yoda-jr)


# IMPORTS
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from mcp.server.fastmcp import FastMCP
import threading




class Variables():
    """This will house multi module vars"""

    
    # CONSTANTS
    console = Console()
    mcp  = FastMCP("Yoda")
    LOCK = threading.RLock()


    # RICH VARS
    panel = Panel(renderable="Developed by NSM Barii", style="bold yellow", border_style="bold red", expand=False)
    table = Table(title="Developed by NSM Barii", style="bold purple", border_style="bold red", title_style="bold purple", header_style="bold purple")
    refresh_per_second = 1
    

    
    iface     = None  # FOR MONITOR MODE
    subnet    = None
    ip_router = None
    ip_local  = None

    

    # =====================
    # MONITOR MODE ATTACKS
    # =====================


    # DEFAULT
    timeout = 15
    channel = None # OR 6
    


    # WAR DRIVING
    mode = 1 # AP's ONLY == 1 else 2 == FOR CLIENTS AND NON BEACON FRAMES


    # EVIL TWIN // BEACON FLOOOOD
    portal_num = 1
    

    # SNIFF FOR SSIDS
    # uses iface
    

    # DEAUTH // CLIENT SNIFFER
    mac_src    = None
    mac_dst    = None
    mac_client = None  # SINGLE CLIENT DEAUTH



