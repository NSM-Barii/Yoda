# TUI IMPORTS
from textual.app import App, ComposeResult
from textual.widgets import RichLog, Header, Footer, Label, DataTable, Tree, TabbedContent, TabPane
from textual.containers import Horizontal
import time
from datetime import datetime

# NSM IMPORTS
from nsm_vars import Variables
from nsm_monitor import Monitor_Runner


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
        tree   = self.query_one("#wifi_tree", Tree)
        branch = tree.root.add(f"[bold green]{ssid}[/bold green]  [dim]{bssid}[/dim]  [cyan]{rssi}dBm[/cyan]", expand=True)
        self._ap_branches[bssid] = branch


    def add_client_to_tree(self, bssid, mac, vendor):
        if bssid not in self._ap_branches: return
        self._ap_branches[bssid].add_leaf(f"[yellow]{mac}[/yellow]  [dim]{vendor or 'Unknown'}[/dim]")


if __name__ == "__main__":
    TUI().run()
