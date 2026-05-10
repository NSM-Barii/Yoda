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



# UI IMPORTS
from rich.panel import Panel



# ETC IMPORTS
import threading, time, sys, argparse


# NSM IMPORTS
from nsm_vars import Variables
from nsm_tui import TUI
import nsm_server_mcp
import nsm_voice_agent


# CONSTANTS
console = Variables.console


def main_no():
    """Start YODA components based on arguments."""

    args = sys.argv[1:]

    start_mcp = "--mcp" in args or "--full" in args
    start_monitoring = "--monitor" in args or "--full" in args

    
    console.print("\n" + "="*60)
    console.print(f"[bold green][!] Yoda Voice-Activated Network Security system!")
    console.print("="*60)


    if start_mcp:

        console.print("[+] Starting MCP Server in background...")
        threading.Thread(target=nsm_server_mcp.main, daemon=True, name="MCP-Server").start()
        time.sleep(1) 


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


def main():
    """This will be used to start main program"""

    data = (
        "[bold cyan]\n Wireless Reconnesiance System"
        "[bold yellow]\n\n BLE • WiFi • LAN"
        "[bold magenta]\n\n Made by NSM Barii"
    )

    panel = Panel(renderable=data, style="bold red")


    parser = argparse.ArgumentParser(
        add_help=False,
        description="This is a Wireless Reconnesiance System designed to monitor surrounds connections and APs"
    )

    parser.add_argument("-i", help="This be used to pass the interface used for monitor mode // for wireless sniffing")
    parser.add_argument("-nfty", help="This will be used to pass the server to push data to for notifications")
    parser.add_argument("-help", help="This will show the help of all arguments and the program title")


    args = parser.parse_args()


    if args.help: 
        console.print(panel)
        parser.print_help()
        return False



    Variables.iface_monitor = args.i or "wlan1"
    Variables.ntfy_path     = args.ntfy or False


    TUI().run()




if __name__ == "__main__": main()
