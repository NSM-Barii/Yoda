# Network Monitor Integration Guide

## What Was Built

Created `/Users/jabarilucien/Documents/nsm_tools/yoda/test/network_monitor.py`

**Key features:**
- ✅ Continuous ARP scanning (every 10 seconds)
- ✅ Device discovery (new devices joining network)
- ✅ Connection tracking (online/offline status)
- ✅ Vendor identification (MAC → manufacturer via API)
- ✅ Event queue for voice alerts
- ✅ Thread-safe operation
- ✅ No Rich UI dependencies (clean, minimal)
- ✅ No TTS dependencies (uses event queue instead)

## Event Types Generated

```python
# New device joins
{
    "type": "device_join",
    "ip": "192.168.1.50",
    "mac": "AA:BB:CC:DD:EE:FF",
    "hostname": "iPhone",
    "vendor": "Apple Inc.",
    "timestamp": 1234567890.0
}

# Device comes back online
{
    "type": "device_online",
    "ip": "192.168.1.50",
    "hostname": "MacBook",
    "timestamp": 1234567890.0
}

# Device goes offline
{
    "type": "device_offline",
    "ip": "192.168.1.50",
    "hostname": "MacBook",
    "offline_duration": 45.2,
    "timestamp": 1234567890.0
}
```

## How to Integrate with MCP Server

### Option 1: Add to server_mcp.py (Recommended)

```python
# At top of server_mcp.py
from network_monitor import NetworkMonitor

# In main() function, start monitor
monitor = NetworkMonitor(interface="en0", subnet="192.168.1.0/24")
monitor.start()

# Add MCP tool to check for events
@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> Sequence[types.TextContent]:

    # ... existing tools ...

    elif name == "check_network_events":
        """Check for network events (device join/leave)"""
        events = []

        # Get all pending events (non-blocking)
        while True:
            event = monitor.get_event(timeout=0)
            if not event:
                break
            events.append(event)

        if not events:
            return [types.TextContent(type="text", text="No new network events")]

        # Format events for voice response
        result = f"Found {len(events)} network events:\n"
        for event in events:
            if event["type"] == "device_join":
                result += f"- New device: {event['hostname']} at {event['ip']} ({event['vendor']})\n"
            elif event["type"] == "device_offline":
                result += f"- Device offline: {event['hostname']} at {event['ip']}\n"
            elif event["type"] == "device_online":
                result += f"- Device back online: {event['hostname']} at {event['ip']}\n"

        return [types.TextContent(type="text", text=result)]

    elif name == "list_network_devices":
        """List all known network devices"""
        devices = monitor.get_online_devices()

        result = f"Found {len(devices)} online devices:\n"
        for device in devices:
            result += f"- {device['hostname']} ({device['ip']}) - {device['vendor']}\n"

        return [types.TextContent(type="text", text=result)]
```

### Option 2: Proactive Voice Alerts (Advanced)

For truly proactive alerts, you'd need to:

1. **Voice agent polls for events periodically**
   - Add a timer in voice_agent.py
   - Every 5 seconds, call `check_network_events` tool
   - If events found, generate TTS alert

2. **MCP server pushes events** (requires MCP protocol extension)
   - Not supported in current MCP stdio transport
   - Would need SSE/HTTP transport for server→client push

**For now, use Option 1** - voice agent can periodically check for events, or user can ask "any network events?"

## Testing Locally

```bash
cd /Users/jabarilucien/Documents/nsm_tools/yoda/test

# Test standalone
sudo python network_monitor.py

# You'll see:
# [NetworkMonitor] Started on en0 monitoring 192.168.1.0/24
# [NetworkMonitor] New device: 192.168.1.10 (iPhone) - Apple Inc.
# EVENT: device_join - {'type': 'device_join', 'ip': '192.168.1.10', ...}
```

## Voice Commands After Integration

- "Check network events" → Gets recent device joins/leaves
- "List network devices" → Shows all online devices
- "Any new devices?" → Checks event queue
- "Show network status" → Device count + recent events

## Next Steps

1. Test network_monitor.py standalone (verify it works on your network)
2. Add to server_mcp.py as shown above
3. Register new tools in ListTools response
4. Test via voice agent
5. (Optional) Add proactive polling in voice agent

## Files Created

- `network_monitor.py` - Core monitoring logic
- `INTEGRATION_GUIDE.md` - This file
- `PROGRESS.md` - Overall progress tracking
