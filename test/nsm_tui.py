# WE ARE TRYING A NEW TUI LIBRARY THAT I FOUND, LETS SEE HOW THIS GOES


# TUI IMPORTS
from textual.app import App, ComposeResult
from textual.widgets import RichLog, Header, Footer
from textual.containers import Horizontal


# ETC IMPORTS
import threading, time, random



# NSM IMPORTS
from nsm_vars import Variables
from nsm_monitor import Monitor_Runner




class TUI(App):
    """This will be used to create a TUI"""


    CSS = """
    #up {
        height: 50%;
    }

    #bottom {
        height: 50%;
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

        with Horizontal(id='up'):
            yield RichLog(id='ble', markup=True)
            yield RichLog(id='wifi', markup=True)
        
        with Horizontal(id="bottom"):
            yield RichLog(id="lan", markup=True)
            yield RichLog(id="output", markup=True)

        yield Footer()
        

    def on_mount(self):
        """This will add shit to created instances"""


        self.query_one('#ble', RichLog).border_title    = "Bluetooth/BLE"
        self.query_one('#wifi', RichLog).border_title   = "WiFi"
        self.query_one('#lan', RichLog).border_title    = "LAN"
        self.query_one('#output', RichLog).border_title = "Output"
        Variables.tui = self

        Monitor_Runner.main()

    

    def push_data(self, id, data):
        """This will be used to push data to RichLog"""
        
        self.query_one(str(id), RichLog).write(data)



if __name__ == "__main__":
    TUI().run()