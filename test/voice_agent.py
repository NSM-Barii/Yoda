"""
Yoda Voice Agent - STT/LLM/TTS Pipeline
========================================

Voice-activated interface for Yoda using LiveKit Agents framework.

## What is LiveKit Agents?
A framework for building real-time voice AI applications.
Learn more: https://docs.livekit.io/agents

## The Voice Pipeline:
┌──────────────┐
│  Microphone  │
└──────┬───────┘
       │ (raw audio)
       ▼
┌──────────────┐
│  Deepgram    │ STT (Speech-to-Text)
│   (STT)      │ Converts audio → text
└──────┬───────┘
       │ ("scan my network")
       ▼
┌──────────────┐
│ OpenAI GPT-4o│ LLM (Reasoning)
│    (LLM)     │ Decides what to do
└──────┬───────┘
       │ (calls MCP tools if needed)
       ▼
┌──────────────┐
│  MCP Server  │ Your network tools
└──────┬───────┘
       │ (returns data)
       ▼
┌──────────────┐
│ OpenAI GPT-4o│ Formats response
└──────┬───────┘
       │ ("I found 12 devices...")
       ▼
┌──────────────┐
│  OpenAI TTS  │ TTS (Text-to-Speech)
│    (TTS)     │ Converts text → audio
└──────┬───────┘
       │ (audio)
       ▼
┌──────────────┐
│   Speaker    │
└──────────────┘

## How LiveKit Works:
- You configure providers (STT, LLM, TTS)
- LiveKit handles the entire pipeline automatically
- You just define behavior via system prompt
- Agent connects to LiveKit Cloud for audio streaming

Learn more:
- Overview: https://docs.livekit.io/agents/overview
- Quickstart: https://docs.livekit.io/agents/quickstart
- Plugins: https://docs.livekit.io/agents/plugins

Usage:
    python voice_agent.py dev      # Development mode (use playground)
    python voice_agent.py console  # Console mode (text only, no voice)

Requirements:
    - MCP server must be running first (python server_mcp.py)
    - .env file with API keys
    - LiveKit Cloud account (free tier works)
"""

import os
import logging
from dotenv import load_dotenv

# ---------------------------------------------------------------------------
# LiveKit Agents Framework
# ---------------------------------------------------------------------------
# Core framework for building the voice agent
# Install: pip install livekit-agents
# Docs: https://docs.livekit.io/agents
from livekit.agents import JobContext, WorkerOptions, cli
from livekit.agents.voice import Agent, AgentSession
from livekit.agents.llm import mcp

# ---------------------------------------------------------------------------
# Provider Plugins
# ---------------------------------------------------------------------------
# LiveKit has pre-built integrations for popular AI services.
# Each plugin handles the API calls, authentication, and streaming.
#
# Available plugins:
# - livekit.plugins.openai (GPT, Whisper, TTS)
# - livekit.plugins.groq (Whisper, Llama)
# - livekit.plugins.google (Gemini)
# - livekit.plugins.deepgram (STT)
# - livekit.plugins.silero (VAD - Voice Activity Detection)
#
# Learn more: https://docs.livekit.io/agents/plugins
from livekit.plugins import openai as lk_openai, deepgram as lk_deepgram, silero

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Load environment variables from .env file
# Install: pip install python-dotenv
load_dotenv()

# Logging setup
logger = logging.getLogger("yoda-voice-agent")
logger.setLevel(logging.INFO)

# Provider Configuration
DEEPGRAM_STT_MODEL = "nova-2"                 # Deepgram STT model
OPENAI_LLM_MODEL = "gpt-4o"                   # Reasoning model
OPENAI_TTS_MODEL = "tts-1"                    # Text-to-speech model
OPENAI_TTS_VOICE = "nova"                     # Voice personality
TTS_SPEED = 1.15                               # Speech rate (1.0 = normal)

# MCP Server URL
# This is where your network tools are exposed
MCP_SERVER_URL = "http://localhost:8000/sse"

# ---------------------------------------------------------------------------
# System Prompt
# ---------------------------------------------------------------------------
# This is THE MOST IMPORTANT part - it defines how the AI behaves.
#
# The LLM reads this prompt before every interaction. It tells the AI:
# - Who it is (identity/personality)
# - What tools it has access to
# - How it should respond (tone, length, style)
# - When to use which tools
#
# Tips for writing good system prompts:
# - Be specific about behavior (not vague)
# - Give examples of good/bad responses
# - Explain WHEN to use tools
# - Define the tone clearly
#
# Learn more about prompt engineering:
# - https://platform.openai.com/docs/guides/prompt-engineering
# - https://docs.anthropic.com/en/docs/build-with-claude/prompt-engineering
# ---------------------------------------------------------------------------

SYSTEM_PROMPT = """
You are YODA - a voice-activated Intrusion Detection System and network security assistant.

## Identity
You are calm, professional, and security-focused. You speak like a seasoned penetration tester -
brief, direct, and knowledgeable. No fluff, just facts.

## Your Capabilities
You have access to network security tools for:
- Network device scanning and enumeration
- Device detail lookup
- Network status monitoring
- (More tools will be added: BLE scanning, WiFi scanning, ARP poisoning, etc.)

## Behavioral Rules

1. **Be Direct**: Skip preamble. When asked to scan, just scan and report results.

2. **Be Brief**: Keep responses to 2-3 sentences maximum. You're a tool, not a chatbot.

3. **Call Tools Silently**: Never say "I'm going to call the scan_network function".
   Just call it and report results.

4. **Use Security Language**:
   - "Scanning subnet..."
   - "12 devices found"
   - "Unknown device flagged"
   - "Target acquired"

5. **Report Data Clearly**: When listing devices, be organized and scannable.

6. **Flag Anomalies**: Point out unknown devices, new connections, or suspicious patterns.

## Response Examples

Good: "Scanning now... 12 devices found. Three unknowns flagged at .105, .148, and .203."
Bad: "I will now use my network scanning capabilities to discover all devices on your network."

Good: "Device at .50 is offline. Last seen 2 hours ago."
Bad: "I have checked the device status and it appears that the device is not currently connected."

## Greeting
When the session starts: "Yoda online. What's the mission?"

Stay focused. Stay sharp. You're a security tool.
""".strip()

# ---------------------------------------------------------------------------
# Provider Setup Functions
# ---------------------------------------------------------------------------
# These functions create instances of each provider (STT, LLM, TTS).
# LiveKit's plugin system makes this simple - just import and configure.
#
# Each provider reads its API key from environment variables automatically:
# - DEEPGRAM_API_KEY
# - OPENAI_API_KEY
#
# Learn more about each provider:
# - Deepgram: https://deepgram.com
# - OpenAI: https://platform.openai.com/docs
# ---------------------------------------------------------------------------

def _build_stt():
    """
    Build Speech-to-Text provider (Deepgram).

    Converts microphone audio into text transcriptions.

    Why Deepgram?
    - $200 free credits
    - Fast, low latency
    - Production-grade accuracy

    Learn more:
    - Deepgram: https://deepgram.com
    - LiveKit Deepgram plugin: https://docs.livekit.io/agents/plugins/deepgram
    """
    logger.info("STT → Deepgram (%s)", DEEPGRAM_STT_MODEL)
    return lk_deepgram.STT(model=DEEPGRAM_STT_MODEL)


def _build_llm():
    """
    Build Large Language Model provider (OpenAI GPT-4o).

    Handles:
    - Understanding user intent from transcribed text
    - Deciding which tools to call
    - Formatting responses based on tool results
    - Following the system prompt personality

    Why GPT-4o?
    - Strong reasoning capabilities
    - Good at tool calling
    - Fast response times
    - Reliable

    Learn more:
    - GPT-4o: https://platform.openai.com/docs/models/gpt-4o
    - Tool calling: https://platform.openai.com/docs/guides/function-calling
    - LiveKit OpenAI plugin: https://docs.livekit.io/agents/plugins/openai
    """
    logger.info("LLM → OpenAI GPT-4o (%s)", OPENAI_LLM_MODEL)
    return lk_openai.LLM(model=OPENAI_LLM_MODEL)


def _build_tts():
    """
    Build Text-to-Speech provider (OpenAI TTS).

    Converts LLM text responses into spoken audio.

    Why OpenAI TTS?
    - High quality, natural-sounding voices
    - Low latency
    - Multiple voice options

    Available voices:
    - alloy, echo, fable, onyx, nova, shimmer
    - "nova" = confident female voice (good for assistant)

    Learn more:
    - OpenAI TTS: https://platform.openai.com/docs/guides/text-to-speech
    - Voice samples: https://platform.openai.com/docs/guides/text-to-speech/voice-options
    """
    logger.info("TTS → OpenAI TTS (%s / %s)", OPENAI_TTS_MODEL, OPENAI_TTS_VOICE)
    return lk_openai.TTS(
        model=OPENAI_TTS_MODEL,
        voice=OPENAI_TTS_VOICE,
        speed=TTS_SPEED
    )


# ---------------------------------------------------------------------------
# Agent Class
# ---------------------------------------------------------------------------
# The Agent is the core of the voice pipeline.
#
# What it does:
# - Connects all providers (STT, LLM, TTS)
# - Connects to MCP server for tool access
# - Manages the conversation flow
# - Handles turn-taking (when to listen vs speak)
#
# The Agent class inherits from livekit.agents.voice.Agent
# and gets a lot of functionality for free:
# - Audio streaming
# - Voice Activity Detection (VAD)
# - Turn detection
# - Session management
#
# Learn more:
# - Agent API: https://docs.livekit.io/agents/api/voice-agent
# - MCP Integration: https://docs.livekit.io/agents/mcp
# ---------------------------------------------------------------------------

class YodaAgent(Agent):
    """
    Voice-activated network security assistant.

    Inherits from LiveKit's Agent class which handles all the
    complex audio streaming and conversation management.
    """

    def __init__(self, stt, llm, tts) -> None:
        """
        Initialize the agent with configured providers.

        Args:
            stt: Speech-to-text provider instance
            llm: Language model provider instance
            tts: Text-to-speech provider instance
        """
        super().__init__(
            # System prompt - defines personality and behavior
            instructions=SYSTEM_PROMPT,

            # Providers
            stt=stt,  # Deepgram
            llm=llm,  # OpenAI GPT-4o
            tts=tts,  # OpenAI TTS

            # Voice Activity Detection
            # Silero VAD detects when the user is speaking vs silent
            # This helps with turn-taking (when to listen vs respond)
            # Learn more: https://github.com/snakers4/silero-vad
            vad=silero.VAD.load(),

            # MCP Server Connection
            # This connects the agent to your network tools
            # The LLM can now discover and call your tools
            mcp_servers=[
                mcp.MCPServerHTTP(
                    url=MCP_SERVER_URL,
                    transport_type="sse",
                    client_session_timeout_seconds=30,
                ),
            ],
        )

    async def on_enter(self) -> None:
        """
        Called when the agent joins the room.

        This is where you can add initialization behavior like
        greeting the user, running startup checks, etc.
        """
        # Generate the greeting message
        # We use generate_reply() to make the LLM speak
        await self.session.generate_reply(
            instructions="Greet the user with: 'Yoda online. What's the mission?'"
        )


# ---------------------------------------------------------------------------
# LiveKit Entry Point
# ---------------------------------------------------------------------------
# This is where LiveKit starts your agent.
#
# The entrypoint function:
# 1. Receives a JobContext with room information
# 2. Builds the providers
# 3. Creates an AgentSession
# 4. Starts the agent in the room
#
# The agent then listens for audio, processes it through the pipeline,
# and responds via voice.
#
# Learn more:
# - Entry points: https://docs.livekit.io/agents/build/entrypoint
# - JobContext: https://docs.livekit.io/agents/api/job-context
# ---------------------------------------------------------------------------

async def entrypoint(ctx: JobContext) -> None:
    """
    Main entry point for the LiveKit voice agent.

    Args:
        ctx: JobContext containing room info and connection details
    """
    logger.info("Yoda Voice Agent starting - Room: %s", ctx.room.name)

    # Build provider instances
    stt = _build_stt()
    llm = _build_llm()
    tts = _build_tts()

    # Create agent session
    # AgentSession manages the conversation lifecycle
    session = AgentSession(
        # Turn detection mode
        # "vad" = use Voice Activity Detection to detect when user stops talking
        # "stt" = wait for STT to signal end of speech
        turn_detection="vad",

        # Endpointing delay
        # How long to wait (in seconds) after user stops talking
        # before processing the audio
        # Too short = cuts off user mid-sentence
        # Too long = feels sluggish
        min_endpointing_delay=0.3,
    )

    # Start the agent in the room
    await session.start(
        agent=YodaAgent(stt=stt, llm=llm, tts=tts),
        room=ctx.room,
    )

    logger.info("Yoda Voice Agent active and listening...")


# ---------------------------------------------------------------------------
# CLI Entry Point
# ---------------------------------------------------------------------------
# LiveKit Agents CLI handles the connection to LiveKit Cloud.
#
# Run modes:
# - dev: Development mode using LiveKit Playground
# - console: Text-only mode (no voice)
# - start: Production mode (auto-connects to room)
#
# Learn more:
# - CLI docs: https://docs.livekit.io/agents/cli
# - Playground: https://agents-playground.livekit.io
# ---------------------------------------------------------------------------

def main():
    """
    Run the voice agent via LiveKit CLI.

    Usage:
        python voice_agent.py dev       # Development mode
        python voice_agent.py console   # Text-only mode
    """
    cli.run_app(WorkerOptions(entrypoint_fnc=entrypoint))


def dev():
    """
    Convenience wrapper for dev mode.

    Allows running just `python voice_agent.py` without specifying 'dev'.
    Automatically injects the 'dev' command if no args provided.
    """
    import sys
    if len(sys.argv) == 1:
        sys.argv.append("dev")
    main()


if __name__ == "__main__":
    dev()
