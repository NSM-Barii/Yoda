# THIS WILL HOUSE MULTI-MODULE VARS (post yoda-jr)


# IMPORTS
from rich.console import Console
from mcp.server.fastmcp import FastMCP





class Variables():
    """This will house multi module vars"""

    
    # CONSTANTS
    console = Console()
    mcp = FastMCP("Yoda")
    

    
    iface     = None  # FOR MONITOR MODE
    subnet    = None
    ip_router = None
    ip_local  = None
