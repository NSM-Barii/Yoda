# Yoda Voice Agent Upgrade - Implementation Roadmap

> Upgrading Yoda's voice system from basic TTS/STT to a modern AI voice agent with LiveKit + LLM architecture

---

## Vision

Transform Yoda from a basic voice-activated IDS into an intelligent conversational network security assistant with:
- Natural language understanding via LLM
- Real-time voice interaction
- AI-powered network analysis
- Expandable tool ecosystem (ARP, BLE, WiFi scanning, deauth attacks, etc.)

---

## Architecture Overview

```
┌─────────────────────────────────────────┐
│  Voice Agent (LiveKit)                  │
│  - STT: Speech-to-Text                  │
│  - LLM: Reasoning & Tool Selection      │
│  - TTS: Text-to-Speech                  │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  MCP Server (FastMCP)                   │
│  - Exposes network tools via SSE        │
│  - Tool orchestration                   │
└─────────────────┬───────────────────────┘
                  │
                  ▼
┌─────────────────────────────────────────┐
│  Network Security Tools (Yoda Modules)  │
│  - ARP Scanning & Poisoning             │
│  - BLE Device Discovery                 │
│  - WiFi SSID Scanning                   │
│  - Deauth Attacks                       │
│  - Network Device Enumeration           │
│  - Traffic Analysis                     │
└─────────────────────────────────────────┘
```

---

## Three-Phase Implementation Plan

### Phase 1: Get It Working (Cloud-Heavy)
**Goal:** Functional voice-controlled IDS with minimal local processing

**Components:**
- **STT:** Groq Whisper (cloud, free)
- **LLM:** OpenAI GPT-4o (cloud, ~$0.02/interaction)
- **TTS:** OpenAI TTS "nova" (cloud, ~$0.015/interaction)
- **Tools:** Local (existing Yoda modules)

**Pros:**
- Fast to implement (use yoda-jr structure as-is)
- Fast response times (2-4s)
- Free/cheap to run

**Cons:**
- Tool results sent to cloud LLM
- Privacy concerns for real pentests
- Requires internet

**Deliverables:**
- [x] Port yoda-jr voice architecture into Yoda
- [ ] Set up MCP server with existing network tools
- [ ] Configure Gemini API
- [ ] Wire up LiveKit agent
- [ ] Test basic voice commands ("scan my network", "list devices")

---

### Phase 2: Hybrid (Local Audio, Cloud LLM)
**Goal:** Keep voice data private, LLM still in cloud

**Components:**
- **STT:** Faster-Whisper (local, GPU-accelerated)
- **TTS:** Piper TTS (local, CPU)
- **LLM:** Gemini 2.5 Flash (cloud)
- **Tools:** Local

**Pros:**
- Audio never leaves machine
- Still fast LLM responses
- Better privacy than Phase 1

**Cons:**
- Tool results still go to cloud
- Requires local STT/TTS setup

**Deliverables:**
- [ ] Install & configure Faster-Whisper
- [ ] Install & configure Piper TTS
- [ ] Add provider switching in config
- [ ] Test local audio pipeline
- [ ] Benchmark response times

---

### Phase 3: Full Offline (Production)
**Goal:** Complete privacy, no cloud dependencies

**Components:**
- **STT:** Faster-Whisper (local)
- **TTS:** Piper TTS (local)
- **LLM:** Ollama + Llama 3.1 8B/70B (local)
- **Tools:** Local

**Pros:**
- 100% private - zero data leaves your network
- No internet required during pentests
- Complete control

**Cons:**
- Requires GPU for fast LLM inference (12GB+ VRAM recommended)
- Slower responses without good hardware (3-15s)
- More setup complexity

**Hardware Requirements:**
| Component | Minimum | Recommended | Ideal |
|-----------|---------|-------------|-------|
| CPU | i5/Ryzen 5 | i7/Ryzen 7 | Any |
| RAM | 16GB | 32GB | 64GB |
| GPU | None (slow) | RTX 3060 12GB | RTX 4090 24GB |
| Storage | 50GB | 100GB | 200GB |

**Response Times:**
- No GPU: 8-15s
- RTX 3060: 2-4s
- RTX 4090: 1-2s

**Deliverables:**
- [ ] Set up Ollama server (local or dedicated box)
- [ ] Install Llama 3.1 8B model
- [ ] Configure LLM provider switching
- [ ] Benchmark performance on target hardware
- [ ] Optimize model selection (3B vs 8B vs 70B)
- [ ] Test full offline mode

---

## Network Tools to Integrate

These will be exposed as MCP tools callable by voice:

### Existing (from current Yoda):
- [x] `get_network_devices()` - List all devices on network
- [x] `arp_poison_attack()` - ARP poisoning for device kick
- [x] `get_network_summary()` - Device count, statistics

### To Add:
- [ ] `scan_ble_devices()` - Bluetooth Low Energy discovery
- [ ] `scan_wifi_ssids()` - WiFi network discovery
- [ ] `deauth_attack()` - WiFi deauthentication
- [ ] `port_scan()` - Port scanning on target
- [ ] `get_device_details(ip)` - Deep dive on specific device
- [ ] `monitor_traffic()` - Live traffic analysis
- [ ] `detect_anomalies()` - AI-powered threat detection

---

## Voice Agent Personality

**Name:** YODA (or F.R.I.D.A.Y. style - user decides)

**Tone:**
- Calm, professional, security-focused
- Brief and direct during active scans
- Conversational but not chatty
- Uses pentest terminology naturally

**Example interactions:**
```
User: "What's on my network?"
Yoda: "Scanning now, boss... I've got 12 active devices. Want the breakdown?"

User: "Yeah, brief me."
Yoda: "Three phones, two laptops, your router, a smart TV, and five IoT devices.
       Two unknowns flagged - MAC addresses I don't recognize."

User: "Kick the unknowns off."
Yoda: "Launching ARP poison on both targets... They're offline. Want me to keep them blocked?"
```

---

## Migration Strategy

**Current Yoda Structure:**
```
yoda/
├── nsm_modules/          # Network scanning tools
├── yoda_modules/         # Voice control (old Vosk/gTTS)
├── web_modules/          # Dashboard
└── yoda/main.py          # Entry point
```

**New Structure:**
```
yoda/
├── nsm_modules/          # Keep - network tools
├── voice_agent/          # NEW - port from yoda-jr
│   ├── agent_yoda.py     # LiveKit agent
│   ├── server_mcp.py     # MCP server
│   └── config.py         # Provider configs
├── tools/                # NEW - MCP tool wrappers
│   ├── network.py        # Wraps nsm_modules
│   ├── bluetooth.py      # BLE scanning
│   └── wifi.py           # WiFi operations
├── web_modules/          # Keep - dashboard
└── yoda/main.py          # Update - new entry
```

---

## Configuration Structure

**`.env` file:**
```bash
# Phase Control
VOICE_PHASE=1  # 1=cloud, 2=hybrid, 3=offline

# Phase 1 (Cloud - OpenAI + Groq)
OPENAI_API_KEY=your_key_here
GROQ_API_KEY=your_key_here
LIVEKIT_URL=wss://your-project.livekit.cloud
LIVEKIT_API_KEY=your_key
LIVEKIT_API_SECRET=your_secret

# Phase 3 (Local LLM)
OLLAMA_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1:8b

# Network Config
DEFAULT_INTERFACE=wlan0
DEFAULT_SUBNET=192.168.1.0/24
```

---

## Success Metrics

**Phase 1 Complete:**
- Voice command → network scan → voice response working
- Response time < 5s
- Can control basic Yoda features via voice

**Phase 2 Complete:**
- Audio processing fully local
- No voice data sent to cloud
- Response time < 4s

**Phase 3 Complete:**
- Fully offline operation
- Response time < 5s (with recommended hardware)
- Can run on air-gapped pentest networks

---

## Next Steps

1. **Immediate:** Set up Gemini API key
2. **Week 1:** Port yoda-jr voice architecture → Phase 1 working
3. **Week 2:** Add all network tools as MCP tools
4. **Week 3:** Test Phase 1 in real pentest scenario
5. **Month 2:** Move to Phase 2 (local audio)
6. **Month 3:** Acquire GPU hardware, implement Phase 3

---

## Reference Projects

- **yoda-jr:** Voice architecture reference (LiveKit + MCP pattern)
- **FastMCP:** Tool server framework
- **LiveKit Agents:** Real-time voice pipeline
- **Ollama:** Local LLM serving
- **Faster-Whisper:** Optimized local STT

---

**Built by NSM Barii** | Ethical Pentesting & Network Security
