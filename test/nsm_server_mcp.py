# THIS SERVER WILL BE USED TO EXPOSE THE MCP SERVER


# IMPORTS
from mcp.server.fastmcp import FastMCP
from nsm_wifi import WiFi, SSID_Sniffer, Client_Sniffer, Deauth_Attacker, Evil_Twin, Beacon_Flooder, War_Driving
from nsm_ble import Bluetooth
from nsm_vars import Variables
import asyncio

mcp = FastMCP(
    name="yoda-network-tools",
    instructions=(
        "You are YODA's network security toolkit. "
        "Provide network scanning, WiFi enumeration, Bluetooth discovery, and penetration testing tools. "
        "Execute commands directly when requested. Be precise and security-focused."
    ),
)


# ========================================
# NETWORK TOOLS
# ========================================

@mcp.tool()
def network_scan_arp(subnet: str = "192.168.1.0/24"):
    """
    Scan local network using ARP to find all active devices.

    Use this when the user asks to:
    - "scan my network" or "ARP scan"
    - "find devices on the network"
    - "what devices are connected"
    - "show me network devices"

    Returns device info: IP address, MAC address, hostname, vendor.
    """
    Variables.subnet = subnet
    return WiFi.network_scan_arp(subnet=subnet)


@mcp.tool()
def scan_bluetooth_devices(duration: int = 5):
    """
    Scan for Bluetooth/BLE devices in the area.

    Use this when the user asks to:
    - "scan for Bluetooth devices"
    - "find BLE devices"
    - "what Bluetooth devices are nearby"
    - "show me Bluetooth"

    Returns: MAC, RSSI, name, service UUIDs, manufacturer data.
    """
    return asyncio.run(Bluetooth.sniff_for_clients_in_the_area(duration=duration, verbose=False))


@mcp.tool()
def ssid_sniffer(iface: str = "wlan1", timeout: int = 15):
    """
    Sniff for WiFi SSIDs/access points in the area (monitor mode).

    Args:
        iface: Monitor mode interface (wlan0, wlan1, etc.)
        timeout: Scan duration in seconds

    Use this when the user asks to:
    - "sniff for SSIDs"
    - "find access points"
    - "show me WiFi networks"
    - "scan for APs"

    Returns: SSID, MAC, RSSI, vendor, encryption, frequency, channel.
    """
    Variables.iface = iface
    Variables.timeout = timeout
    return SSID_Sniffer.main()


@mcp.tool()
def client_sniffer(target_mac: str = "", iface: str = "wlan1", channel: int = 6):
    """
    Sniff for clients connected to a specific access point.

    Args:
        target_mac: Target AP MAC address (BSSID)
        iface: Monitor mode interface
        channel: WiFi channel to monitor

    Use this when the user asks to:
    - "find clients on this network"
    - "show me connected devices"
    - "sniff clients from [SSID/MAC]"
    - "who's connected to this AP"

    Sends small deauth packets to trigger reconnections and capture client MACs.
    """
    Variables.mac_client = target_mac
    Variables.iface = iface
    Variables.channel = channel
    return Client_Sniffer.main()


@mcp.tool()
def deauth_attacker(target_mac: str = "", source_mac: str = "", iface: str = "wlan1", channel: int = 6, count: int = 10):
    """
    Perform deauthentication attack on WiFi clients or access points.

    Args:
        target_mac: Target MAC address (AP or client)
        source_mac: Source MAC address (spoof as AP or client)
        iface: Monitor mode interface
        channel: WiFi channel
        count: Number of deauth packets to send

    Use this when the user asks to:
    - "deauth this network"
    - "kick clients off WiFi"
    - "disconnect [MAC/SSID]"
    - "jam this access point"

    Sends deauth frames to disconnect clients from APs.
    """
    Variables.mac_dst = target_mac
    Variables.mac_src = source_mac
    Variables.iface = iface
    Variables.channel = channel
    Variables.count = count
    return Deauth_Attacker.main()


@mcp.tool()
def evil_twin(portal_choice: int = 2, iface: str = "wlan1", channel: int = 6):
    """
    Launch Evil Twin attack (fake AP with captive portal).

    Args:
        portal_choice: Portal type number (1-20) - chooses both SSID and portal page
        iface: Monitor mode interface
        channel: WiFi channel

    Use this when the user asks to:
    - "create fake WiFi"
    - "launch evil twin"
    - "set up captive portal"
    - "create rogue AP"

    Portal options (SSID is auto-set based on choice):
    1=LA Fitness, 2=Starbucks WiFi, 3=Airport_Free_WiFi, 4=Marriott_Guest,
    5=SUBWAY_Free_WiFi, 6=McDonalds_Free_WiFi, 7=Target Guest WiFi, 8=Walmart WiFi,
    9=Hospital_Guest, 10=Public_Library_WiFi, 11=Campus_WiFi, 12=Panera WiFi,
    13=BestBuy_Guest, 14=CORP_Guest_WiFi, 15=Hilton_Honors, 16=Delta Sky Club,
    17=Apple Store, 18=YMCA_Member_WiFi, 19=Whole_Foods_WiFi, 20=CVS WiFi

    Creates fake access point that mimics legitimate networks.
    Captures credentials via captive portal.
    """
    Variables.portal_num = portal_choice
    Variables.iface = iface
    Variables.channel = channel
    return Evil_Twin.main()


@mcp.tool()
def beacon_flooder(ssid_type: int = 1, iface: str = "wlan1", channel: int = 6):
    """
    Flood the area with fake WiFi beacons (SSID spam).

    Args:
        ssid_type: SSID list type (1=trolling, 2=christmas, 3=custom)
        iface: Monitor mode interface
        channel: WiFi channel to flood

    Use this when the user asks to:
    - "flood fake SSIDs"
    - "spam WiFi networks"
    - "create fake access points"
    - "beacon flood"

    SSID Types:
    1 = Trolling SSIDs (FBI_Surveillance_Van, PrettyFlyForAWiFi, etc.)
    2 = Christmas SSIDs (MerryChristmas, HappyHolidays, etc.)
    3 = Custom SSIDs (comma-separated list)

    Creates hundreds of fake WiFi networks to clutter WiFi scanners.
    """
    Variables.portal_num = ssid_type
    Variables.iface = iface
    Variables.channel = channel
    return Beacon_Flooder.main()


@mcp.tool()
def war_driving(mode: int = 1, iface: str = "wlan1"):
    """
    War driving mode - passively collect WiFi networks and clients.

    Args:
        mode: Scan mode (1=APs only, 2=clients and APs)
        iface: Monitor mode interface

    Use this when the user asks to:
    - "start war driving"
    - "collect WiFi data"
    - "map WiFi networks"
    - "passive WiFi scan"

    Mode 1: Collect access points (SSIDs, BSSIDs, encryption, signal)
    Mode 2: Collect access points + clients + probe requests

    Continuously sniffs for APs, clients, and probe requests.
    Tracks GPS coordinates (if available).
    """
    Variables.mode = mode
    Variables.iface = iface
    return War_Driving.main(mode=mode)




def main():
    """Run the MCP server."""
    print("\n" + "="*60)
    print("Yoda MCP Server Starting...")
    print("="*60)
    print(f"Server URL: http://localhost:8000/sse")
    print("="*60 + "\n")

    mcp.run(transport='sse')


if __name__ == "__main__":
    main()
