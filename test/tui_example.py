from textual.app import App, ComposeResult
from textual.widgets import RichLog, Header, Footer
from textual.containers import Horizontal
import threading
import time


class MonitorTUI(App):

    CSS = """
    #top {
        height: 70%;
    }

    #ble {
        border: round red;
        width: 1fr;
    }

    #wifi {
        border: round green;
        width: 1fr;
    }

    #output {
        border: round yellow;
        height: 1fr;
    }
    """

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal(id="top"):
            yield RichLog(id="ble",  markup=True)
            yield RichLog(id="wifi", markup=True)
        yield RichLog(id="output", markup=True)
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#ble",    RichLog).border_title = "BLE"
        self.query_one("#wifi",   RichLog).border_title = "WiFi"
        self.query_one("#output", RichLog).border_title = "Output"

        threading.Thread(target=self._push_data, daemon=True).start()

    def _push_data(self):
        time.sleep(1)
        self.call_from_thread(self.query_one("#ble",    RichLog).write, "[green]hello from ble[/green]")
        self.call_from_thread(self.query_one("#wifi",   RichLog).write, "[yellow]hello from wifi[/yellow]")
        self.call_from_thread(self.query_one("#output", RichLog).write, "[red]hello from output[/red]")


if __name__ == "__main__":
    MonitorTUI().run()
