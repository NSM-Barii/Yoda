"""
YODA Voice Agent
================
Voice-activated network security assistant using LiveKit Agents framework.

Features:
- Full voice conversation (STT → LLM → TTS)
- MCP tool integration for network security
- Proactive notifications from monitoring events

Usage:
    python nsm_voice_agent.py dev      # Development mode
    python nsm_voice_agent.py console  # Text-only mode
"""

import os
import logging
import asyncio
from dotenv import load_dotenv

from livekit.agents import JobContext, WorkerOptions, cli
from livekit.agents.voice import Agent, AgentSession
from livekit.agents.llm import mcp
from livekit.plugins import openai as lk_openai, deepgram as lk_deepgram, silero

from nsm_vars import Variables

load_dotenv()

logger = logging.getLogger("yoda-voice-agent")
logger.setLevel(logging.INFO)

# Configuration
DEEPGRAM_STT_MODEL = "nova-2"
OPENAI_LLM_MODEL = "gpt-4o"
OPENAI_TTS_MODEL = "tts-1"
OPENAI_TTS_VOICE = "nova"
TTS_SPEED = 1.15
MCP_SERVER_URL = "http://localhost:8000/sse"

SYSTEM_PROMPT = """
You are YODA - a voice-activated Intrusion Detection System and network security assistant.

## Identity
You are calm, professional, and security-focused. You speak like a seasoned penetration tester - brief, direct, and knowledgeable. No fluff, just facts.

## Your Capabilities
You have access to network security tools for:
- ARP network scanning (network_scan_arp)
- WiFi SSID scanning (ssid_sniffer)
- Bluetooth/BLE device discovery (scan_bluetooth_devices)
- Client enumeration (client_sniffer)
- Deauth attacks (deauth_attacker)
- Evil Twin attacks (evil_twin)
- Beacon flooding (beacon_flooder)
- War driving (war_driving)

## CRITICAL RULES

1. **NEVER say tool names or function names**. No "network_scan_arp", no "I'm going to call...", nothing technical.

2. **Before calling any tool, say something natural** like "Scanning now..." or "On it..." Then call the tool silently.

3. **Call tools immediately when requested**. Don't ask for confirmation. Just do it.

4. **Use the ACTUAL tools**. Never make up or hallucinate scan results. If you say you found devices, you MUST have called a tool.

5. **Report results directly**. After the tool returns data, summarize it briefly.

## Behavioral Rules

1. **Be Direct**: Skip preamble. When asked to scan, just scan and report results.

2. **Be Brief**: Keep responses to 2-3 sentences maximum. You're a tool, not a chatbot.

3. **Use Security Language**:
   - "Scanning subnet..."
   - "12 devices found"
   - "Unknown device flagged"
   - "Target acquired"

4. **Report Data Clearly**: When listing devices, be organized and scannable.

5. **Flag Anomalies**: Point out unknown devices, new connections, or suspicious patterns.

## Response Examples

Good: "Scanning now... [calls tool silently] 12 devices found. Three unknowns flagged at .105, .148, and .203."
Bad: "I will now use my network_scan_arp function to discover all devices on your network."

Good: "On it... [calls tool] Device at .50 is offline. Last seen 2 hours ago."
Bad: "Let me check the device status for you using the appropriate tool."

## Greeting
When the session starts: "Yoda online. What's the mission?"

Stay focused. Stay sharp. You're a security tool.
""".strip()


def _build_stt():
    logger.info("STT → Deepgram (%s)", DEEPGRAM_STT_MODEL)
    return lk_deepgram.STT(model=DEEPGRAM_STT_MODEL)


def _build_llm():
    logger.info("LLM → OpenAI GPT-4o (%s)", OPENAI_LLM_MODEL)
    return lk_openai.LLM(model=OPENAI_LLM_MODEL)


def _build_tts():
    logger.info("TTS → OpenAI TTS (%s / %s)", OPENAI_TTS_MODEL, OPENAI_TTS_VOICE)
    return lk_openai.TTS(
        model=OPENAI_TTS_MODEL,
        voice=OPENAI_TTS_VOICE,
        speed=TTS_SPEED
    )


class YodaAgent(Agent):
    """Voice-activated network security assistant with proactive notifications."""

    def __init__(self, stt, llm, tts) -> None:
        super().__init__(
            instructions=SYSTEM_PROMPT,
            stt=stt,
            llm=llm,
            tts=tts,
            vad=silero.VAD.load(),
            mcp_servers=[
                mcp.MCPServerHTTP(
                    url=MCP_SERVER_URL,
                    transport_type="sse",
                    client_session_timeout_seconds=30,
                ),
            ],
        )
        self._monitoring_task = None

    async def on_enter(self) -> None:
        """Called when agent joins the room."""

        # 1. Greet the user
        await self.session.generate_reply(
            instructions="Greet the user with: 'Yoda online. What's the mission?'"
        )

        # 2. Start background monitoring task for proactive notifications
        self._monitoring_task = asyncio.create_task(self._monitor_events())
        logger.info("Proactive monitoring notifications started")

    async def _monitor_events(self):
        """Background task that monitors event queue and speaks notifications."""

        while True:
            try:
                # Check if there are events in the queue
                if not Variables.EVENT_QUEUE.empty():
                    event_text = Variables.EVENT_QUEUE.get()

                    # Speak the event proactively
                    logger.info(f"Speaking notification: {event_text}")
                    await self.session.say(event_text)

                    Variables.EVENT_QUEUE.task_done()

                # Check every second
                await asyncio.sleep(1)

            except Exception as e:
                logger.error(f"Monitoring notification error: {e}")
                await asyncio.sleep(5)


async def entrypoint(ctx: JobContext) -> None:
    """Main entry point for the LiveKit voice agent."""

    logger.info("Yoda Voice Agent starting - Room: %s", ctx.room.name)
    logger.info("MCP Server URL: %s", MCP_SERVER_URL)

    stt = _build_stt()
    llm = _build_llm()
    tts = _build_tts()

    session = AgentSession(
        turn_detection="vad",
        min_endpointing_delay=0.3,
    )

    await session.start(
        agent=YodaAgent(stt=stt, llm=llm, tts=tts),
        room=ctx.room,
    )

    logger.info("Yoda Voice Agent active and listening...")


def main():
    """Run the voice agent via LiveKit CLI."""
    cli.run_app(WorkerOptions(entrypoint_fnc=entrypoint))


def dev():
    """Convenience wrapper for dev mode."""
    import sys
    if len(sys.argv) == 1:
        sys.argv.append("dev")
    main()


if __name__ == "__main__":
    dev()
