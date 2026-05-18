# THIS MODULE WILL HANDLE TEXT TO SPEECH VIA PYTTSX3


# IMPORTS
import threading, logging
import pyttsx3

# NSM IMPORTS
from nsm_vars import Variables


log = logging.getLogger("yoda-tts")


class TTS():
    """Reads from Variables.EVENT_QUEUE and speaks via pyttsx3"""


    @classmethod
    def _worker(cls):
        """Background thread — pulls from EVENT_QUEUE and speaks"""

        engine = pyttsx3.init()
        while True:
            text = Variables.EVENT_QUEUE.get()
            if text is None: break
            try:
                engine.say(text)
                engine.runAndWait()
            except Exception as e:
                log.error(f"TTS error: {e}")
            Variables.EVENT_QUEUE.task_done()


    @classmethod
    def _stats_announcer(cls):
        """Periodically speaks current RF stats"""

        while True:
            threading.Event().wait(timeout=Variables.tts_interval)

            from nsm_monitor import Monitor_Bluetooth, Monitor_WiFi
            ble     = len(Monitor_Bluetooth.live_map)
            aps     = len(Monitor_WiFi.live_map)
            clients = sum(len(ap["clients"]) for ap in Monitor_WiFi.live_map.values())

            Variables.push_event(f"{ble} BLE devices, {aps} access points, {clients} clients")


    @classmethod
    def start(cls):
        """Start the TTS worker thread"""

        threading.Thread(target=cls._worker,          daemon=True, name="TTS-Worker").start()
        threading.Thread(target=cls._stats_announcer, daemon=True, name="TTS-Stats").start()
        Variables.push_event("Yoda online")
