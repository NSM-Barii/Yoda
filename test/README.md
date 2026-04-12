# Yoda Voice Agent

Voice-activated Intrusion Detection System powered by LiveKit Agents + MCP.

## Two Setup Options

### Option A: Cloud LiveKit (Recommended for Getting Started)
- ✅ Run MCP + voice agent on **remote Linux server**
- ✅ Connect from **any device** via browser
- ✅ No Docker needed
- ❌ Free tier quota limits

### Option B: Self-Hosted LiveKit (For Unlimited Local Use)
- ✅ Unlimited usage, no quotas
- ✅ Everything runs locally
- ❌ **All components must be on same Linux machine**
- ❌ Requires Docker

---

## Quick Start (Cloud LiveKit)

**Best for:** Testing, demos, remote access

### Prerequisites
- Linux server with Python 3.13+
- OpenAI API key
- Deepgram API key
- LiveKit Cloud account (free tier)

### Setup

1. **Get API Keys**
   - OpenAI: https://platform.openai.com/api-keys
   - Deepgram: https://console.deepgram.com
   - LiveKit: https://cloud.livekit.io

2. **Configure `.env`**
   ```bash
   OPENAI_API_KEY=sk-...
   DEEPGRAM_API_KEY=...
   LIVEKIT_URL=wss://your-project.livekit.cloud
   LIVEKIT_API_KEY=APIxxxxxxxxx
   LIVEKIT_API_SECRET=xxxxxxxxx
   ```

3. **Start MCP Server** (Terminal 1)
   ```bash
   cd yoda/test
   source venv/bin/activate
   sudo venv/bin/python server_mcp.py
   ```

4. **Start Voice Agent** (Terminal 2)
   ```bash
   cd yoda/test
   source venv/bin/activate
   export SSL_CERT_FILE=$(python -m certifi)
   python voice_agent.py dev
   ```

5. **Connect from Browser**
   - Go to: https://agents-playground.livekit.io
   - Connect to your LiveKit project
   - Start talking!

**That's it.** Your MCP server and voice agent run on Linux, you access via any web browser.

**Note:** No need to clone the agents-playground repo for cloud setup. Just use the hosted version.

---

## Full Setup (Self-Hosted LiveKit)

**Best for:** Unlimited usage, offline operation, no quotas

### ⚠️ IMPORTANT: All components must run on the SAME Linux machine
- Docker LiveKit server
- MCP server
- Voice agent
- Playground UI

You cannot run Docker on one machine and access from another easily.

### Prerequisites
- Linux machine with Docker
- Python 3.13+
- Node.js 18+

### One-Time Setup

**1. Install Dependencies**
```bash
# Node.js and pnpm
sudo apt install nodejs npm
npm install -g pnpm

# Docker (if not installed)
curl -fsSL https://get.docker.com | sh
```

**2. Start LiveKit Docker Container**
```bash
docker run -d --name livekit-server \
  -p 7880:7880 -p 7881:7881 -p 7882:7882/udp \
  -e LIVEKIT_KEYS="devkey: devsecret" \
  livekit/livekit-server --dev

# Verify it's running
docker ps | grep livekit
```

**3. Clone and Setup Playground**

The playground provides a web UI to talk to your voice agent. For self-hosted, you need to run it locally.

```bash
cd yoda/test
git clone https://github.com/livekit/agents-playground
cd agents-playground
pnpm install

# Create config
cat > .env.local << 'EOF'
LIVEKIT_API_KEY=devkey
LIVEKIT_API_SECRET=devsecret
NEXT_PUBLIC_LIVEKIT_URL=ws://localhost:7880
EOF
```

**4. Configure Voice Agent `.env`**
```bash
OPENAI_API_KEY=sk-...
DEEPGRAM_API_KEY=...

# Self-hosted LiveKit (DO NOT CHANGE)
LIVEKIT_URL=ws://localhost:7880
LIVEKIT_API_KEY=devkey
LIVEKIT_API_SECRET=devsecret
```

### Daily Usage (Self-Hosted)

**Terminal 1: Start MCP Server**
```bash
cd yoda/test
source venv/bin/activate
sudo venv/bin/python server_mcp.py
```

**Terminal 2: Start Voice Agent**
```bash
cd yoda/test
source venv/bin/activate
export SSL_CERT_FILE=$(python -m certifi)
python voice_agent.py dev
```

**Terminal 3: Start Playground**
```bash
cd yoda/test/agents-playground
pnpm run dev
```

**Browser:** Open `http://localhost:3000` on the **same Linux machine**

---

## Architecture

**Cloud Setup:**
```
Browser (anywhere) → LiveKit Cloud → Voice Agent (Linux) → MCP Server (Linux)
```

**Self-Hosted Setup:**
```
Browser (localhost) → LiveKit Docker → Voice Agent → MCP Server
        ↑
   All on same Linux machine
```

---

## Available Voice Commands

- "scan my network" → ARP scan
- "scan for WiFi networks" → WiFi SSID sniffing
- "scan for Bluetooth devices" → BLE discovery
- "sniff for access points" → Monitor mode WiFi scan
- "find clients on this network" → Client enumeration
- "deauth this network" → Deauth attack
- "launch evil twin" → Fake AP + captive portal
- "flood fake SSIDs" → Beacon flooding
- "start war driving" → Passive WiFi collection

---

## Troubleshooting

### Voice agent not calling tools

**Check MCP server logs:**
```bash
# Should see: "Processing request of type ListToolsRequest"
```

**Check voice agent logs:**
```bash
# Should see: MCP connection attempts
```

### Self-hosted: Can't access playground from browser

**Problem:** Trying to access from different machine

**Solution:** Access from `http://localhost:3000` on the **same Linux machine** running Docker

### Cloud: Quota exceeded

**Problem:** LiveKit Cloud free tier maxed out

**Solutions:**
1. Create new LiveKit account with different email
2. Wait for monthly reset
3. Upgrade to paid plan ($29/month)
4. Switch to self-hosted setup

### OpenAI API errors

**Problem:** Billing not set up or quota exceeded

**Solution:**
1. Check: https://platform.openai.com/account/billing
2. Add payment method
3. Set billing alerts

---

## Costs

### Cloud LiveKit
- LiveKit: Free tier (limited), $29/month after
- Deepgram: $200 free credits, then $0.0043/min
- OpenAI GPT-4o: $2.50/1M input, $10/1M output
- OpenAI TTS: $15/1M characters

**Monthly estimate:** $5-30 depending on usage

### Self-Hosted LiveKit
- LiveKit: **FREE** (runs on Docker)
- Deepgram: $200 free credits, then $0.0043/min
- OpenAI GPT-4o: $2.50/1M input, $10/1M output
- OpenAI TTS: $15/1M characters

**Monthly estimate:** $5-10 for regular testing

---

## Files

- `server_mcp.py` - Exposes network tools via MCP
- `voice_agent.py` - Voice pipeline (STT → LLM → TTS)
- `.env` - API keys and config
- `agents-playground/` - Local UI (self-hosted only)

---

## Which Setup Should I Use?

**Use Cloud LiveKit if:**
- You want to test quickly
- You want remote access
- You're okay with quotas

**Use Self-Hosted if:**
- You need unlimited usage
- You want full control
- You have a dedicated Linux machine
- You want zero recurring LiveKit costs
