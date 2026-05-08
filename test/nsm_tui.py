# TUI IMPORTS
from textual.app import App, ComposeResult
from textual.widgets import RichLog, Header, Footer, Label, DataTable, Tree, TabbedContent, TabPane
from textual.containers import Horizontal

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
        self.query_one("#ble",  RichLog).border_title = "Bluetooth/BLE"
        self.query_one("#wifi", RichLog).border_title = "WiFi"

        ble_table = self.query_one("#ble_table", DataTable)
        ble_table.add_columns("#", "RSSI", "MAC", "Name", "Vendor", "Manufacturer", "Status")

        ap_table = self.query_one("#ap_table", DataTable)
        ap_table.add_columns("#", "RSSI", "SSID", "BSSID", "Vendor", "Channel", "Clients", "Status")

        self.query_one("#wifi_tree", Tree).root.expand()

        self._ble_rows    = {}
        self._ap_rows     = {}
        self._ap_branches = {}

        Variables.tui = self
        Monitor_Runner.main()


    def push_data(self, id, data):
        self.query_one(str(id), RichLog).write(data)


    def update_stats(self, ble: int, wifi_aps: int, wifi_clients: int):
        self.query_one("#stats", Label).update(
            f"[bold red]BLE: {ble}[/bold red]  [dim]|[/dim]  [bold green]APs: {wifi_aps}[/bold green]  [dim]|[/dim]  [bold blue]Clients: {wifi_clients}[/bold blue]"
        )


    def upsert_ble(self, mac, vendor, manuf, name, rssi, status="online"):
        table = self.query_one("#ble_table", DataTable)
        color = "green" if status == "online" else "dim"

        if mac in self._ble_rows:
            table.update_cell(mac, "RSSI",   str(rssi))
            table.update_cell(mac, "Status", status)
        else:
            num = len(self._ble_rows) + 1
            row = (str(num), str(rssi), f"[{color}]{mac}", name or "-", vendor or "-", manuf or "-", status)
            self._ble_rows[mac] = True
            table.add_row(*row, key=mac)


    def upsert_ap(self, bssid, ssid, vendor, channel, rssi, clients, status="online"):
        table = self.query_one("#ap_table", DataTable)
        color = "green" if status == "online" else "dim"

        if bssid in self._ap_rows:
            table.update_cell(bssid, "RSSI",    str(rssi))
            table.update_cell(bssid, "Clients", str(clients))
            table.update_cell(bssid, "Status",  status)
        else:
            num = len(self._ap_rows) + 1
            row = (str(num), str(rssi), f"[{color}]{ssid}", bssid, vendor or "-", str(channel), str(clients), status)
            self._ap_rows[bssid] = True
            table.add_row(*row, key=bssid)


    def add_ap_to_tree(self, bssid, ssid, rssi):
        tree   = self.query_one("#wifi_tree", Tree)
        branch = tree.root.add(f"[bold green]{ssid}[/bold green]  [dim]{bssid}[/dim]  [cyan]{rssi}dBm[/cyan]", expand=True)
        self._ap_branches[bssid] = branch


    def add_client_to_tree(self, bssid, mac, vendor):
        if bssid not in self._ap_branches: return
        self._ap_branches[bssid].add_leaf(f"[yellow]{mac}[/yellow]  [dim]{vendor or 'Unknown'}[/dim]")


if __name__ == "__main__":
    TUI().run()
