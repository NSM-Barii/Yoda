# THIS FILE WILL BE USED TO CREATE SMOOTH USER INTERFACES


# TUI IMPORTS
from textual.app import App, ComposeResult
from textual.widgets import RichLog, Header, Footer, Label, DataTable, Tree, TabbedContent, TabPane
from textual.containers import Horizontal


# ETC IMPORTS
import time, pyfiglet
from datetime import datetime

# NSM IMPORTS
from nsm_vars import Variables
from nsm_monitor import Monitor_Runner


# CONSTANTS
console = Variables.console


class TUI(App):

    CSS = """
    #stats {
        height: 3;
        width: auto;
        content-align: left middle;
        padding: 0 2;
        border: round grey;
    }
    TabbedContent { height: 1fr; }
    TabPane       { height: 1fr; }
    #up           { height: 1fr; }
    #ble          { width: 1fr; border: round red;   }
    #wifi         { width: 1fr; border: round green; }
    """

    def compose(self):
        """This will initialize the TUI"""


        yield Header(id="yoda")
        yield Label("BLE: 0  |  APs: 0  |  Clients: 0", id="stats")

        with TabbedContent():
            with TabPane("Dashboard"):
                with Horizontal(id="up"):
                    yield RichLog(id="ble",  markup=True)
                    yield RichLog(id="wifi", markup=True)

            with TabPane("BLE Devices"):
                yield DataTable(id="ble_table", cursor_type="row")

            with TabPane("WiFi APs"):
                yield DataTable(id="ap_table", cursor_type="row")

            with TabPane("WiFi Tree"):
                yield Tree("Access Points", id="wifi_tree")

        yield Footer()


    def on_mount(self):
        """This will add to said initialized TUI"""

        self.query_one("#ble",  RichLog).border_title = "Bluetooth/BLE"
        self.query_one("#wifi", RichLog).border_title = "WiFi"

        ble_table = self.query_one("#ble_table", DataTable)
        _, self._ck_ble_rssi, _, _, _, _, self._ck_ble_first, self._ck_ble_session, self._ck_ble_status = ble_table.add_columns(
            "#", "RSSI", "MAC", "Name", "Vendor", "Manufacturer", "First Seen", "Session", "Status"
        )

        ap_table = self.query_one("#ap_table", DataTable)
        _, self._ck_ap_rssi, _, _, _, _, self._ck_ap_clients, self._ck_ap_first, self._ck_ap_session, self._ck_ap_status = ap_table.add_columns(
            "#", "RSSI", "SSID", "BSSID", "Vendor", "Channel", "Clients", "First Seen", "Session", "Status"
        )

        self.query_one("#wifi_tree", Tree).root.expand()

        self._ble_rows      = {}
        self._ble_first_ts  = {}
        self._ap_rows       = {}
        self._ap_first_ts   = {}
        self._ap_branches   = {}

        Variables.tui = self
        Monitor_Runner.main()


    def push_data(self, id, data):
        """This will be used to push data"""

        self.query_one(str(id), RichLog).write(data)


    def update_stats(self, ble: int, wifi_aps: int, wifi_clients: int):
        """This will be used to update stats"""

        self.query_one("#stats", Label).update(f"[bold red]BLE: {ble}[/bold red]  [dim]|[/dim]  [bold green]APs: {wifi_aps}[/bold green]  [dim]|[/dim]  [bold blue]Clients: {wifi_clients}[/bold blue]")


    @staticmethod
    def _fmt_session(start_ts):
        """This will be used to get time, this lowkey makes sense now that i look like it"""

        elapsed = int(time.time() - start_ts)
        h, rem  = divmod(elapsed, 3600)
        m, s    = divmod(rem, 60)
        if h:    return f"{h}h {m}m"
        if m:    return f"{m}m {s}s"
        return f"{s}s"


    def upsert_ble(self, mac, vendor, manuf, name, rssi, status="online"):
        table = self.query_one("#ble_table", DataTable)
        color = "green" if status == "online" else "dim"

        if mac in self._ble_rows:
            key     = self._ble_rows[mac]
            session = self._fmt_session(self._ble_first_ts[mac])
            try: table.update_cell(key, self._ck_ble_rssi,    str(rssi))
            except: pass
            try: table.update_cell(key, self._ck_ble_session, session)
            except: pass
            try: table.update_cell(key, self._ck_ble_status,  status)
            except: pass
        else:
            now       = time.time()
            first_str = datetime.now().strftime("%H:%M:%S")
            self._ble_first_ts[mac] = now
            num = len(self._ble_rows) + 1
            row = (str(num), str(rssi), f"[{color}]{mac}", name or "-", vendor or "-", manuf or "-", first_str, "0s", status)
            self._ble_rows[mac] = table.add_row(*row)


    def upsert_ap(self, bssid, ssid, vendor, channel, rssi, clients, status="online"):
        table = self.query_one("#ap_table", DataTable)
        color = "green" if status == "online" else "dim"

        if bssid in self._ap_rows:
            key     = self._ap_rows[bssid]
            session = self._fmt_session(self._ap_first_ts[bssid])
            try: table.update_cell(key, self._ck_ap_rssi,    str(rssi))
            except: pass
            try: table.update_cell(key, self._ck_ap_clients, str(clients))
            except: pass
            try: table.update_cell(key, self._ck_ap_session, session)
            except: pass
            try: table.update_cell(key, self._ck_ap_status,  status)
            except: pass
        else:
            now       = time.time()
            first_str = datetime.now().strftime("%H:%M:%S")
            self._ap_first_ts[bssid] = now
            num = len(self._ap_rows) + 1
            row = (str(num), str(rssi), f"[{color}]{ssid}", bssid, vendor or "-", str(channel), str(clients), first_str, "0s", status)
            self._ap_rows[bssid] = table.add_row(*row)


    def add_ap_to_tree(self, bssid, ssid, rssi):
        """This will ad an ap to a tree"""

        tree   = self.query_one("#wifi_tree", Tree)
        branch = tree.root.add(f"[bold green]{ssid}[/bold green]  [dim]{bssid}[/dim]  [cyan]{rssi}dBm[/cyan]", expand=True)
        self._ap_branches[bssid] = branch


    def add_client_to_tree(self, bssid, mac, vendor):
        """This will add clients to the tree"""

        if bssid not in self._ap_branches: return
        self._ap_branches[bssid].add_leaf(f"[yellow]{mac}[/yellow]  [dim]{vendor or 'Unknown'}[/dim]")



class CLI():
    """This will be used to get custom vars from user before transitioning to the TUI"""


    @classmethod
    def _print_welcome(cls):
        """This will be used to print Yoda"""


        text = pyfiglet.format(text="Yoda", font="bloody")
        console.print(text, "\nWireless reconnesiance framework for spectrum spying")


    
    @classmethod
    def _check_vars(cls):
        """This will check def vars, if not true then summon assign"""

        
        # FOR NOW THIS WILL RETURN TRUE INDEFINETLY TO CONTINUE RUNNING CLI ALL THE TIME
        return True


        if not Variables.ntfy_ble_path: 
            return False
        
        if Variables.ntfy_wifi_path:
            return False
    

    @classmethod
    def _default_vars(cls):
        """This will print the default vars as the user can just keep tapping enter"""

        c1 = "bold green"
        c2 = "bold yellow"
        c3 = "bold red"
        c4 = "bold blue"


        stats = (
            f"[{c1}] [+] WiFi Interface:[{c4}] {Variables.iface_monitor}"
            #f"\n[{c1}] [+] BT Interface:[{c4}] {Variables.bface}"
            f"\n[{c1}] [+] NTFY wifi_path:[{c4}] {Variables.ntfy_ble_path}"
            f"\n[{c1}] [+] NTFY ble_path:[{c4}] {Variables.ntfy_wifi_path}"
            f"\n[{c1}] [+] WiFi client_idle:[{c4}] {Variables.wifi_client_idle}"
            f"\n[{c1}] [+] WiFi client_offline:[{c4}] {Variables.wifi_client_offline}"
            f"\n[{c1}] [+] BLE pct_set_unstable:[{c4}] {Variables.pct_set_unstable}"
            f"\n[{c1}] [+] BLE pct_set_drop:[{c4}] {Variables.pct_set_drop}"
            f"\n[{c1}] [+] WiFi Hop Delay:[{c4}] {Variables.wifi_hop_delay}s"
            f"\n[{c1}] [+] Verbose:[{c4}] {Variables.verbose}"
        )

        console.print(f"[bold green][+] Default Variables below!!!")
        console.print(
            f"\n[{c1}]=========   Default Variables   =========\n",
            stats,
            f"\n[{c1}]=================================\n"
        )
        console.print(f"\n\n[bold red][!] Keeping tapping enter if you dont know what values to input, or read the README.md you skidd!!!")
        time.sleep(2)


    @classmethod
    def _set_vars(cls):
        """This will be used to set vars via RICH cli"""


        c1 = "bold red"
        c2 = "bold yellow"
        c3 = "bold green"
        c4 = "bold blue"
        c5 = "yellow"

        p1 = "[+]"
        p2 = "[*]"


        iface = console.input(f"[{c5}]{p2} iface_monitor:[/{c5}] ")

        wifi_hops      = console.input(f"[{c5}]{p2} wifi_hops:[/{c5}] ")
        wifi_hop_delay = console.input(f"[{c5}]{p2} wifi_hop_delay:[/{c5}] ")

        wifi_client_idle    = console.input(f"[{c5}]{p2} wifi_client_idle:[/{c5}] ")
        wifi_client_offline = console.input(f"[{c5}]{p2} wifi_client_offline:[/{c5}] ")

        pct_set_unstable = console.input(f"[{c5}]{p2} pct_set_unstable:[/{c5}] ")
        pct_set_drop     = console.input(f"[{c5}]{p2} pct_set_drop:[/{c5}] ")

        ntfy_ble_path  = console.input(f"[{c5}]{p2} ntfy_ble_path:[/{c5}] ")
        ntfy_wifi_path = console.input(f"[{c5}]{p2} ntfy_wifi_path:[/{c5}] ")


        if wifi_hops in Variables.presets: Variables.wifi_hops = Variables.presets[wifi_hops]


        Variables.iface_monitor       = iface
        Variables.wifi_hops           = wifi_hops
        Variables.wifi_hop_delay      = wifi_hop_delay
        Variables.ntfy_ble_path       = ntfy_ble_path
        Variables.ntfy_wifi_path      = ntfy_wifi_path
        Variables.wifi_client_idle    = wifi_client_idle
        Variables.wifi_client_offline = wifi_client_offline
        Variables.pct_set_unstable    = pct_set_unstable
        Variables.pct_set_drop        = pct_set_drop


    @classmethod
    def _print_vars(cls):
        """This will print out the vars vals"""


        c1 = "bold green"
        c2 = "bold yellow"
        c3 = "bold red"
        c4 = "bold blue"



        stats = (
            f"[{c1}] [+] WiFi Interface:[{c4}] {Variables.iface_monitor}"
            #f"\n[{c1}] [+] BT Interface:[{c4}] {Variables.bface}"
            f"\n[{c1}] [+] NTFY wifi_path:[{c4}] {Variables.ntfy_ble_path}"
            f"\n[{c1}] [+] NTFY ble_path:[{c4}] {Variables.ntfy_wifi_path}"
            f"\n[{c1}] [+] WiFi client_idle:[{c4}] {Variables.wifi_client_idle}"
            f"\n[{c1}] [+] WiFi client_offline:[{c4}] {Variables.wifi_client_offline}"
            f"\n[{c1}] [+] BLE pct_set_unstable:[{c4}] {Variables.pct_set_unstable}"
            f"\n[{c1}] [+] BLE pct_set_drop:[{c4}] {Variables.pct_set_drop}"
            f"\n[{c1}] [+] WiFi Hop Delay:[{c4}] {Variables.wifi_hop_delay}s"
            f"\n[{c1}] [+] Verbose:[{c4}] {Variables.verbose}"
        )

        console.print(
            f"\n[{c1}]=========   CONSTANTS   =========\n",
            stats,
            f"\n[{c1}]=================================\n"
        )
    

    @classmethod
    def main(cls):
        """This will control cli var assignment"""
  

        cls._default_vars()      
        cls._default_vars()
        if cls._check_vars(): cls._set_vars()
        cls._print_vars()
        
        time.sleep(2)
        console.input(f"\n\n[bold blue][!] Press Enter to Acknowledge your Vars!")






if __name__ == "__main__":
    TUI().run()
