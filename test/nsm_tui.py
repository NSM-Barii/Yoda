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
        height: 40%;
    }

    #bottom {
        height: 30%;
    }

    #ble {
        width: 1fr;
        border: round red;
    }

    #wifi {
        width: 1fr;
        border: round green;
    }

    #t1 {
        width: 1fr;
        border: round blue;
    }

    #t2 {
        width: 1fr;
        border: round blue;
    }

    #output {
        height: 30%;
        border: round yellow;
    }
    """



    def compose(self):
        """This will initalize the log"""


        yield Header(id="yoda")
        with Horizontal(id='up'):
            yield RichLog(id='ble', markup=True)
            yield RichLog(id='wifi', markup=True)
        #with Horizontal(id='bottom'):
            #yield RichLog(id='t1', markup=True)
            #yield RichLog(id='t2', markup=True)
    
        yield RichLog(id='output', markup=True)
        yield Footer()
        

    def on_mount(self):
        """This will add shit to created instances"""


        self.query_one('#ble', RichLog).border_title = "Bluetooth/BLE"
        self.query_one('#wifi', RichLog).border_title = "WiFi"
        #self.query_one('#t1', RichLog).border_title = "t1"
        #self.query_one('#t2', RichLog).border_title = "t2"
        Variables.tui = self

        Monitor_Runner.main()

    

    def push_data(self, id, data):
        """This will be used to push data to RichLog"""
        
        self.query_one(str(id), RichLog).write(data)



if __name__ == "__main__":
    TUI().run()