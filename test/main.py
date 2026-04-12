# THIS WILL LAUNCH MODULE WIDE CODE


# ETC IMPORTS
import threading


# NSM IMPORTS
from nsm_vars import Variables
import nsm_server_mcp, nsm_voice_agent


# CONSTANTS
mcp = Variables.mcp
console = Variables.console



def main():
    """Start logic from here"""
    
    
    threading.Thread(target=voice_agent.main(), args=(), daemon=True).start()
    server_mcp.mcp.run(transport="sse")
    


    