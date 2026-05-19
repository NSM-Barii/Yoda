# THIS WILL BE THE START OF SOMETHING GREAT // _archive holds old concept

# UI IMPORTS
from rich.panel import Panel



# ETC IMPORTS
import threading, time, sys, argparse


# NSM IMPORTS
from nsm_vars import Variables
from nsm_tui import TUI, CLI
from nsm_database import Background_Threads
#import nsm_server_mcp
# import nsm_voice_agent


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
        "[bold cyan]  Y O D A[/bold cyan]"
        "\n[dim]  Passive RF Monitoring System[/dim]"
        "\n\n[bold white]  Monitors[/bold white]"
        "\n[bold blue]  •[/bold blue] [white]Bluetooth/BLE[/white]   [dim]— nearby devices, vendors, signal strength[/dim]"
        "\n[bold green]  •[/bold green] [white]WiFi APs[/white]       [dim]— access points, channels, client counts[/dim]"
        "\n[bold yellow]  •[/bold yellow] [white]WiFi Clients[/white]   [dim]— devices connecting to nearby networks[/dim]"
        "\n\n[bold white]  Usage[/bold white]"
        "\n  [dim]python main.py [/dim][cyan]-i wlan1[/cyan]"
        "\n  [dim]python main.py [/dim][cyan]-i wlan1 -ntfy my-topic-123[/cyan]"
        "\n\n[dim]  Made by NSM Barii[/dim]"
    )

    panel = Panel(renderable=data, style="bold red", border_style="bold red", padding=(1, 2))


    parser = argparse.ArgumentParser(
        add_help=False,
        description="Yoda — Passive RF monitoring. Tracks BLE devices, WiFi APs, and clients in your area."
    )

    parser.add_argument("-i",    metavar="IFACE",      help="Monitor mode interface (default: wlan1)")
    parser.add_argument("--bu", type=int, default=25,  help="BLE unstable device threshold (default: 25)")
    parser.add_argument("--bd", type=int, default=25,  help="BLE drop score threshold (default: 25)")
    parser.add_argument("-ntfy", metavar="TOPIC",      help="ntfy topic for push notifications (e.g. my-topic-123)")
    parser.add_argument("-help", action="store_true",  help="Show this help message")
    parser.add_argument("--obs",  action="store_true", help="Obfuscate MACs and SSIDs in the TUI")


    args = parser.parse_args()


    if args.help: 
        console.print(panel)
        parser.print_help()
        return False

    if args.obs: Variables.obfuscate = True

    CLI.main()
    Background_Threads.set_monitor_mode(iface=Variables.iface_monitor)
    TUI().run()






if __name__ == "__main__": main()
