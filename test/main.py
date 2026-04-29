"""
YODA Main Launcher
==================
Starts MCP server, monitoring, and voice agent from one command.

Usage:
    python main.py                    # Voice agent only
    python main.py --mcp              # MCP server + Voice agent
    python main.py --monitor          # Monitoring + Voice agent
    python main.py --full             # Everything (MCP + Monitoring + Voice)
"""

import threading
import sys
import time

# NSM IMPORTS
from nsm_vars import Variables
import nsm_server_mcp
import nsm_voice_agent


def main():
    """Start YODA components based on arguments."""

    args = sys.argv[1:]

    # Parse arguments
    start_mcp = "--mcp" in args or "--full" in args
    start_monitoring = "--monitor" in args or "--full" in args

    print("\n" + "="*60)
    print("YODA - Voice-Activated Network Security System")
    print("="*60)

    # Start MCP server
    if start_mcp:
        print("[+] Starting MCP Server in background...")
        threading.Thread(
            target=nsm_server_mcp.main,
            daemon=True,
            name="MCP-Server"
        ).start()
        time.sleep(1)  # Give it a second to start

    # Start monitoring
    if start_monitoring:
        print("[+] Starting Monitoring in background...")

        # Import monitoring modules
        try:
            from nsm_monitor import Monitor_Bluetooth, Monitor_Deauth_Tshark

            # Start BLE monitoring
            threading.Thread(
                target=Monitor_Bluetooth.main,
                daemon=True,
                name="BLE-Monitor"
            ).start()

            # Uncomment to start deauth monitoring
            # threading.Thread(
            #     target=Monitor_Deauth_Tshark.main,
            #     daemon=True,
            #     name="Deauth-Monitor"
            # ).start()

            print("[+] Monitoring active (BLE)")

        except ImportError as e:
            print(f"[!] Monitoring import failed: {e}")

    # Status
    print("\nActive Components:")
    if start_mcp:
        print("  ✓ MCP Server (http://localhost:8000/sse)")
    if start_monitoring:
        print("  ✓ Monitoring (BLE, Deauth)")
    print("  ✓ Voice Agent (starting...)")
    print("\n" + "="*60 + "\n")

    # Start voice agent (foreground - blocks here)
    try:
        nsm_voice_agent.dev()
    except KeyboardInterrupt:
        print("\n[!] Shutting down YODA...")


if __name__ == "__main__":
    main()
