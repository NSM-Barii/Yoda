# THIS MODULE WILL HANDLE TEXT TO SPEECH VIA GTTS + MPG123


# IMPORTS
import io, subprocess, threading, logging
from gtts import gTTS

# NSM IMPORTS
from nsm_vars import Variables


log = logging.getLogger("yoda-tts")


class TTS():
    """Reads from Variables.EVENT_QUEUE and speaks via gTTS + mpg123"""


    @staticmethod
    def _synthesize(text):
        """gTTS --> BytesIO"""

        try:
            buf = io.BytesIO()
            gTTS(text=text, lang="en").write_to_fp(buf)
            buf.seek(0)
            return buf.read()
        except Exception as e:
            log.error(f"gTTS failed: {e}")
            return None


    @staticmethod
    def _play(mp3_bytes):
        """Pipe mp3 bytes --> mpg123 stdin"""

        try:
            proc = subprocess.Popen(
                ["mpg123", "-q", "-"],
                stdin=subprocess.PIPE,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            try:
                proc.communicate(input=mp3_bytes, timeout=30)
            except subprocess.TimeoutExpired:
                log.error("mpg123 timed out, killing")
                proc.kill()
                proc.communicate()
        except FileNotFoundError:
            log.error("mpg123 not found — sudo apt install mpg123")
        except Exception as e:
            log.error(f"Playback error: {e}")


    @classmethod
    def _worker(cls):
        """Background thread — pulls from EVENT_QUEUE and speaks"""

        while True:
            text = Variables.EVENT_QUEUE.get()
            if text is None: break
            mp3 = cls._synthesize(text)
            if mp3: cls._play(mp3)
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

        threading.Thread(target=cls._worker,           daemon=True, name="TTS-Worker").start()
        threading.Thread(target=cls._stats_announcer,  daemon=True, name="TTS-Stats").start()
        Variables.push_event("Yoda online")
