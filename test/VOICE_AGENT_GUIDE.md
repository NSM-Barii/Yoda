# YODA Voice Agent Setup

YODA now has full voice capabilities with proactive notifications, just like FRIDAY.

## Features

1. **Full Voice Conversation**
   - Talk to YODA with your microphone
   - YODA responds via TTS
   - Uses MCP tools for network security operations

2. **Proactive Notifications**
   - Monitoring detects events (unstable BLE, deauth attacks, etc.)
   - YODA automatically speaks alerts while you're in a session
   - No need to ask - YODA tells you what's happening

## Architecture

```
Microphone → STT (Deepgram) → LLM (GPT-4o) → TTS (OpenAI) → Speaker
                                    ↓
                              MCP Tools (network security)

Background Monitoring → EVENT_QUEUE → session.say() → Speaker
```

## Setup

### 1. Install Dependencies

```bash
pip install livekit-agents livekit-plugins-openai livekit-plugins-deepgram livekit-plugins-silero python-dotenv
```

### 2. Configure API Keys

Create `.env` file:

```bash
DEEPGRAM_API_KEY=your_deepgram_key
OPENAI_API_KEY=your_openai_key
LIVEKIT_URL=your_livekit_url
LIVEKIT_API_KEY=your_livekit_key
LIVEKIT_API_SECRET=your_livekit_secret
```

Get free credits:
- Deepgram: https://deepgram.com ($200 free)
- LiveKit: https://livekit.io (free tier)
- OpenAI: https://platform.openai.com

### 3. Start MCP Server

```bash
python nsm_server_mcp.py
```

This exposes your network tools on `http://localhost:8000/sse`

### 4. Start Monitoring (Optional)

If you want proactive notifications, start monitoring:

```bash
python nsm_monitor.py
# or
python main.py  # if you have a main script
```

Monitoring will detect events and push them to `Variables.EVENT_QUEUE`

### 5. Start Voice Agent

```bash
# Development mode (uses LiveKit Playground)
python nsm_voice_agent.py dev

# Console mode (text only, no voice)
python nsm_voice_agent.py console
```

## Usage

### Voice Conversation Examples

**You:** "Scan my network"
**YODA:** "Scanning now... 12 devices found. Three unknowns flagged at .105, .148, and .203."

**You:** "Scan for Bluetooth devices"
**YODA:** "On it... Found 8 BLE devices nearby."

**You:** "What's on channel 6?"
**YODA:** "Scanning channel 6... Two access points detected."

### Proactive Notifications

While you're in a voice session, if monitoring detects something:

**YODA (unprompted):** "Alert. Unstable BLE device detected. Apple device."

**YODA (unprompted):** "Warning. Deauth attack detected. 50 packets per second."

**YODA (unprompted):** "Device stabilized."

## How Proactive Notifications Work

1. **Monitor detects event** (e.g., unstable BLE device)
2. **Calls `Variables.push_event("Alert. Unstable BLE device...")`**
3. **Event goes into `Variables.EVENT_QUEUE`**
4. **Background task in voice agent checks queue every second**
5. **Calls `await self.session.say(event_text)` to speak it**
6. **YODA announces the event while you listen**

## Customization

### Change Voice

Edit `nsm_voice_agent.py`:

```python
OPENAI_TTS_VOICE = "nova"  # Options: alloy, echo, fable, onyx, nova, shimmer
TTS_SPEED = 1.15           # 0.25 to 4.0
```

### Change STT Model

```python
DEEPGRAM_STT_MODEL = "nova-2"  # or "nova", "enhanced", "base"
```

### Change LLM

```python
OPENAI_LLM_MODEL = "gpt-4o"  # or "gpt-4o-mini" for cheaper/faster
```

### Modify Personality

Edit `SYSTEM_PROMPT` in `nsm_voice_agent.py`

### Add More Notifications

In any monitoring code:

```python
from nsm_vars import Variables

# Push event to be spoken
Variables.push_event("Your custom notification here")
```

Events are deduplicated (5 second cooldown) to prevent spam.

## File Structure

```
yoda/test/
├── nsm_voice_agent.py        # Main voice agent (LiveKit)
├── nsm_server_mcp.py          # MCP server exposing tools
├── nsm_monitor.py             # Monitoring with notifications
├── nsm_vars.py                # Shared variables + EVENT_QUEUE
├── .env                       # API keys (create this)
└── VOICE_AGENT_GUIDE.md       # This file
```

## Troubleshooting

### "ModuleNotFoundError: No module named 'livekit'"

```bash
pip install livekit-agents livekit-plugins-openai livekit-plugins-deepgram livekit-plugins-silero
```

### "MCP server connection failed"

Make sure `nsm_server_mcp.py` is running first:

```bash
python nsm_server_mcp.py
```

### "Deepgram API key not found"

Add to `.env`:

```
DEEPGRAM_API_KEY=your_key_here
```

### "No audio output"

Check your system audio settings. LiveKit uses your default output device.

### "Voice agent not speaking notifications"

Make sure:
1. Monitoring is running (`python nsm_monitor.py`)
2. Voice agent is running (`python nsm_voice_agent.py dev`)
3. You're in the LiveKit room/session

## Linux Setup

For Linux (your actual deployment):

Everything works the same! Just make sure:
- Audio output device is configured
- Microphone is accessible
- All dependencies are installed

No macOS-specific code - fully cross-platform.

## Comparison: FRIDAY vs YODA

| Feature | FRIDAY (yoda-jr) | YODA (test) |
|---------|------------------|-------------|
| Voice Conversation | ✅ LiveKit | ✅ LiveKit |
| Proactive Notifications | ✅ Background task | ✅ Background task |
| MCP Tools | ✅ News/Finance | ✅ Network Security |
| STT | Sarvam/Whisper | Deepgram |
| LLM | Gemini/GPT-4o | GPT-4o |
| TTS | OpenAI | OpenAI |
| Personality | Tony Stark AI | Penetration Tester |

Both use the **same architecture** - just different personalities and tools.

## Next Steps

1. ✅ Voice agent configured with proactive notifications
2. Test it: Run MCP server → Run monitoring → Run voice agent
3. Speak to YODA and watch it respond
4. Trigger a monitoring event and hear YODA announce it
5. (Optional) Deploy to Linux with Tesla P4 for offline mode

---

**Created:** 2026-04-29
**Author:** nsm_barii
