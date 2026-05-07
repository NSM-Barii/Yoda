# WE ARE TRYING A NEW TUI LIBRARY THAT I FOUND, LETS SEE HOW THIS GOES


# TUI IMPORTS
from textual.app import App, ComposeResult
from textual.widgets import RichLog, Header, Footer, Label, DataTable, Tree, TabbedContent, TabPane, Select
from textual.containers import Horizontal


# ETC IMPORTS
import threading, time, random



# NSM IMPORTS
from nsm_vars import Variables
from nsm_monitor import Monitor_Runner




class TUI(App):
    """This will be used to create a TUI"""


    CSS = """
    #stats{
        height: 5;
        border: round grey;
    }
    #stats_ble, #stats_aps, #stats_clients{
        width: 1fr;
        border: round yellow;
        content-align: center middle;
    }
    TabbedContent {
        height: 1fr;
    }
    TabPane {
        height: 1fr;
    }
    #up {
        height: 1fr;
    }

    #bottom {
        height: 1fr;
    }

    #ble {
        width: 1fr;
        border: round red;
    }

    #wifi {
        width: 1fr;
        border: round green;
    }

    #lan {
        width: 1fr;
        border: round green;
    }

    #output {
        width: 1fr;
        border: round red;
    }

    """



    def compose(self):
        """This will initalize the log"""


        yield Header(id="yoda")

        with Horizontal(id="stats"):
            yield Label("", id="stats_ble")
            yield Label("", id="stats_aps")
            yield Label("", id="stats_clients")

        with TabbedContent():

            with TabPane("Dashboard"):
                with Horizontal(id='up'):
                    yield RichLog(id='ble',  markup=True)
                    yield RichLog(id='wifi', markup=True)

            with TabPane("BLE Devices"):
                yield Select([("All", "all"), ("Online", "online"), ("Offline", "offline")], id="ble_filter", value="all")
                yield DataTable(id='ble_table', cursor_type="row")

            with TabPane("WiFi APs"):
                yield Select([("All", "all"), ("Online", "online"), ("Offline", "offline")], id="ap_filter", value="all")
                yield DataTable(id="ap_table", cursor_type="row")

            with TabPane("WiFi Tree"):
                yield Tree("Access Points", id="wifi_tree")

        yield Footer()
        

    def on_mount(self):
        """This will add shit to created instances"""


        self.query_one('#ble', RichLog).border_title    = "Bluetooth/BLE"
        self.query_one('#wifi', RichLog).border_title   = "WiFi"
        #self.query_one('#lan', RichLog).border_title    = "LAN"
        #self.query_one('#output', RichLog).border_title = "Output"

        ble_table = self.query_one("#ble_table", DataTable)
        ble_table.add_columns("#", "RSSI", "MAC", "Name", "Vendor", "Manufacturer", "UUIDs", "Status")

        ap_table  = self.query_one("#ap_table",  DataTable)
        ap_table.add_columns("#", "RSSI", "SSID", "BSSID", "Vendor", "Channel", "Clients", "Status")

        self.query_one("#wifi_tree", Tree).root.expand()
        
        self._ble_rows = {}
        self._ap_rows  = {}
        self._ap_branches = {}

        Variables.tui = self

        Monitor_Runner.main()

    

    def push_data(self, id, data):
        """This will be used to push data to RichLog"""
        
        self.query_one(str(id), RichLog).write(data)
    

    def update_stats(self, ble:int, wifi_aps:int, wifi_clients:int):
        """This will be used to update the status bar"""


        if ble:          self.query_one("#stats_ble",     Label).update(f"[bold red]BLE: {ble}")
        if wifi_aps:     self.query_one("#stats_aps",     Label).update(f"[bold green]APs: {wifi_aps}")
        if wifi_clients: self.query_one("#stats_clients", Label).update(f"[bold blue]Clients: {wifi_clients}")


    def upsert_ble(self, mac, vendor, manuf, name, rssi, status="online"):
        """This will add or update a BLE device in the table"""


        table = self.query_one("#ble_table", DataTable)
        color = "green" if status == "online" else "dim"
        num   = len(self._ble_rows) + 1
        row   = (str(num), str(rssi), f"[{color}]{mac}", name or "-", vendor or "-", manuf or "-", status)

        if mac in self._ble_rows:
            table.update_cell(self._ble_rows[mac], "RSSI",   str(rssi))
            table.update_cell(self._ble_rows[mac], "Status", status)
        else:
            key = table.add_row(*row)
            self._ble_rows[mac] = key


    def upsert_ap(self, bssid, ssid, vendor, channel, rssi, clients, status="online"):
        """This will add or update a WiFi AP in the table"""


        table = self.query_one("#ap_table", DataTable)
        color = "green" if status == "online" else "dim"
        num   = len(self._ap_rows) + 1
        row   = (str(num), str(rssi), f"[{color}]{ssid}", bssid, vendor or "-", str(channel), str(clients), status)

        if bssid in self._ap_rows:
            table.update_cell(self._ap_rows[bssid], "RSSI",    str(rssi))
            table.update_cell(self._ap_rows[bssid], "Clients", str(clients))
            table.update_cell(self._ap_rows[bssid], "Status",  status)
        else:
            key = table.add_row(*row)
            self._ap_rows[bssid] = key


    def add_ap_to_tree(self, bssid, ssid, rssi):
        """This will add an AP branch to the WiFi tree"""


        tree   = self.query_one("#wifi_tree", Tree)
        branch = tree.root.add(f"[bold green]{ssid}[/bold green]  [dim]{bssid}[/dim]  [cyan]{rssi}dBm[/cyan]", expand=True)
        self._ap_branches[bssid] = branch


    def add_client_to_tree(self, bssid, mac, vendor):
        """This will add a client leaf under its AP in the WiFi tree"""


        if bssid not in self._ap_branches: return

        self._ap_branches[bssid].add_leaf(f"[yellow]{mac}[/yellow]  [dim]{vendor or 'Unknown'}[/dim]")
 



if __name__ == "__main__":
    TUI().run()