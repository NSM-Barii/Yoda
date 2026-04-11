# Yoda Voice Agent - Reference Implementation

This directory contains **heavily documented reference code** for building Yoda's voice interface.

**Important:** This is a learning reference, not production code. Study it, understand it, then rebuild it yourself.

---

## What's In Here

| File | What It Does | Key Concepts |
|------|--------------|--------------|
| `server_mcp.py` | MCP server that exposes network tools | FastMCP, tool decoration, SSE transport |
| `voice_agent.py` | Voice pipeline (STT→LLM→TTS) | LiveKit Agents, provider plugins, system prompts |
| `.env.example` | API keys and configuration | Environment variables |

---

## How To Use This

### Step 1: Read First, Code Later

**Don't run this code yet.** Read it thoroughly:

1. **Read `server_mcp.py`**
   - Understand what FastMCP does
   - See how `@mcp.tool()` works
   - Look at the tool function pattern
   - Follow the documentation links

2. **Read `voice_agent.py`**
   - Understand the voice pipeline flow
   - See how providers are configured
   - Study the system prompt structure
   - Follow the documentation links

3. **Look up concepts you don't understand**
   - What is SSE (Server-Sent Events)?
   - How does LiveKit handle audio streaming?
   - What is Voice Activity Detection?
   - How does MCP tool calling work?

### Step 2: Set Up Your Learning Environment

**Install dependencies:**
```bash
cd test/
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install livekit-agents fastmcp python-dotenv
pip install livekit-plugins-openai livekit-plugins-groq livekit-plugins-silero
```

**Get API keys:**
1. **OpenAI:** https://platform.openai.com/api-keys
2. **Groq:** https://console.groq.com/keys (free tier)
3. **LiveKit:** https://cloud.livekit.io (free tier)

**Configure environment:**
```bash
cp .env.example .env
# Edit .env and add your API keys
```

### Step 3: Test Individual Components

**Test MCP server only:**
```bash
# Terminal 1
python server_mcp.py

# Terminal 2 - test it works
curl http://localhost:8000/sse
# Should see an SSE stream connection
```

**Test voice agent only (without MCP):**
- Comment out the `mcp_servers` line in `voice_agent.py`
- Run `python voice_agent.py dev`
- Test basic voice interaction without tools

**Test them together:**
```bash
# Terminal 1 - MCP server
python server_mcp.py

# Terminal 2 - Voice agent
python voice_agent.py dev

# Browser - LiveKit Playground
# Go to https://agents-playground.livekit.io
# Connect to your room
# Say "scan my network"
```

### Step 4: Study the Documentation

**Core concepts to master:**

**For MCP Server:**
- [ ] What is MCP? (https://modelcontextprotocol.io)
- [ ] How does FastMCP work? (https://github.com/jlowin/fastmcp)
- [ ] What makes a good tool docstring?
- [ ] How does the LLM discover tools?
- [ ] What is SSE and why use it?

**For Voice Agent:**
- [ ] LiveKit Agents overview (https://docs.livekit.io/agents/overview)
- [ ] How do provider plugins work? (https://docs.livekit.io/agents/plugins)
- [ ] What is Voice Activity Detection?
- [ ] How does turn detection work?
- [ ] How does the Agent class manage conversations?
- [ ] What makes a good system prompt?

### Step 5: Rebuild From Scratch

Once you understand the concepts:

1. **Close this reference code**
2. **Create a new file**
3. **Build your own version from scratch**
4. **Use the official docs** as your guide
5. **Reference this code only when stuck**

Your version might look similar (it's a framework pattern), but you'll understand every line because YOU built it.

---

## Key Learning Resources

### FastMCP
- Repo: https://github.com/jlowin/fastmcp
- Examples: https://github.com/jlowin/fastmcp/tree/main/examples

### LiveKit Agents
- Overview: https://docs.livekit.io/agents/overview
- Quickstart: https://docs.livekit.io/agents/quickstart
- Plugins: https://docs.livekit.io/agents/plugins
- MCP Integration: https://docs.livekit.io/agents/mcp
- Examples: https://github.com/livekit/agents/tree/main/examples

### MCP Protocol
- Spec: https://modelcontextprotocol.io
- Tool Calling: https://modelcontextprotocol.io/docs/concepts/tools

### Provider Docs
- OpenAI GPT: https://platform.openai.com/docs/models/gpt-4o
- OpenAI TTS: https://platform.openai.com/docs/guides/text-to-speech
- Groq Whisper: https://console.groq.com/docs/speech-text

---

## Understanding the Code Structure

### MCP Server (`server_mcp.py`)

```python
# 1. Import FastMCP
from mcp.server.fastmcp import FastMCP

# 2. Create server instance
mcp = FastMCP(name="...")

# 3. Define tools (decorated functions)
@mcp.tool()
def my_tool():
    """Docstring - LLM reads this"""
    # Your code
    return {"result": "data"}

# 4. Run the server
mcp.run(transport='sse')
```

**Key points:**
- `@mcp.tool()` makes a function callable by the LLM
- Docstring is CRITICAL - it's how the LLM knows when to use the tool
- Return values must be JSON-serializable
- Server runs on port 8000 by default

### Voice Agent (`voice_agent.py`)

```python
# 1. Import framework and plugins
from livekit.agents import Agent
from livekit.plugins import openai, groq

# 2. Build providers
stt = groq.STT(model="whisper-large-v3-turbo")
llm = openai.LLM(model="gpt-4o")
tts = openai.TTS(model="tts-1", voice="nova")

# 3. Create agent
agent = Agent(
    instructions="System prompt...",
    stt=stt,
    llm=llm,
    tts=tts,
    mcp_servers=["http://localhost:8000/sse"]
)

# 4. Start session
await session.start(agent=agent, room=ctx.room)
```

**Key points:**
- Providers handle the API calls (you just configure them)
- System prompt defines the AI's personality
- Agent class wires everything together automatically
- LiveKit handles all audio streaming, turn-taking, etc.

---

## Common Questions

**Q: Do I need to understand the LiveKit internals?**
A: No. LiveKit abstracts away the hard parts (audio streaming, WebRTC, etc.). You just need to understand how to configure providers and define behavior.

**Q: How does the LLM know which tool to call?**
A: It reads the tool's name and docstring. That's why clear, specific docstrings are critical.

**Q: Can I use different providers?**
A: Yes! LiveKit has plugins for many providers (Gemini, Deepgram, ElevenLabs, etc.). Just swap the plugin import and configuration.

**Q: Why is the system prompt so important?**
A: The LLM reads it before every interaction. It's the only way to control personality, tone, and behavior since you can't modify the LLM itself.

**Q: How does the audio streaming work?**
A: LiveKit handles it via WebRTC. Your agent connects to LiveKit Cloud, which manages the audio rooms. You don't code the streaming part.

---

## Next Steps

1. **Read both files thoroughly** (don't skip the comments)
2. **Look up unfamiliar concepts** (follow the documentation links)
3. **Test the code** (get it running)
4. **Study the official docs** (understand the frameworks)
5. **Rebuild from scratch** (make it yours)

---

**Remember:** The goal isn't to copy this code. It's to understand the patterns well enough to build your own version confidently.
