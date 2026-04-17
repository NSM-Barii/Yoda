# THIS WILL BE FOR BLUETOOTH/BLE LOGIC



#  UI IMPORTS
from rich.table import Table



# IMPORTS
from bleak import BleakClient, BleakScanner
import asyncio, time, threading


# NSM IMPORTS
from nsm_vars import Variables
from nsm_database import DataBase, Extensions


# CONSTANTS
console = Variables.console
DataBase = DataBase.Bluetooth



class Bluetooth():
    """This will house logic for bluetooth"""


    
    @staticmethod
    def _get_manuf(manuf_data):
        """This will convert manuf data"""


        d = {}
        hex = None
        if not manuf_data: return False

        for key, value in manuf_data.items():
            id = key; hex = value.hex() 

        company = DataBase.get_manufacturer(id=key, data=hex)

        console.print(company)
        return company


    
    @staticmethod
    async def sniff_for_clients_in_the_area(duration=5, verbose=False) -> list:
        """This will scan the area for bluetooth/ble devices for a total of x seconds and return all the devices found along with its advertised info.
        rssi, mac, name, service uuid, manuf data, 
        """



        devices = []
        scanner = BleakScanner()




        try:
            
            await scanner.start()
            await asyncio.sleep(duration)
            await scanner.stop()


            raw_devices = scanner.discovered_devices_and_advertisement_data


            for mac, (device, data) in raw_devices.items():



                
                rssi = data.rssi
                tx   = data.tx_power
                name = data.local_name
                adv  = data.service_uuids
                manufacturer = Bluetooth._get_manuf(manuf_data=data.manufacturer_data)
                d = (mac, rssi, tx, name, adv, manufacturer)
                devices.append(d)
            

            if verbose: console.print(devices)

            console.print(f"\n[bold green][+] Total Devices Found:[bold yellow] {len(devices)}")
            return devices
             


        except Exception as e: 
            console.print(f"[bold red][-] Bluetooth Exception Error:[bold yellow] {e}"); return False
    







if __name__ == "__main__": 

    Monitor_Bluetooth.main()