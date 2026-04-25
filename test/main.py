# THIS WILL LAUNCH MODULE WIDE CODE

import threading
import sys

# NSM IMPORTS
from nsm_vars import Variables
import nsm_server_mcp
import nsm_voice_agent


def main():
    """Start logic from here"""

    # Decide mode
    full_mode = "--full" in sys.argv

    if full_mode:
        print("[+] Running FULL mode (MCP + Voice)")
        
        # Start MCP server in background
        threading.Thread(
            target=nsm_server_mcp.main,
            daemon=True
        ).start()

    else:
        print("[+] Running ALERT mode (TTS only)")

    # Run voice agent (MAIN THREAD)
    nsm_voice_agent.dev()


if __name__ == "__main__":
    main()