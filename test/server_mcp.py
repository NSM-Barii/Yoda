# THIS SERVER WILL BE USED TO EXPOSE THE MCP SERVER


# IMPORTS
from mcp.server.fastmcp import FastMCP
from wifi import WiFi
from ble import Bluetooth
import asyncio
import inspect

mcp = FastMCP(name="yoda-network-tools")


# ========================================
# DYNAMIC TOOL REGISTRATION
# ========================================

def register_class_methods(cls, async_methods=False):
    """Register all public methods from a class as MCP tools"""

    for name, method in inspect.getmembers(cls, predicate=inspect.ismethod):

        if name.startswith('_'): continue

        def make_wrapper(m):
            if async_methods:
                def wrapper(**kwargs):
                    return asyncio.run(m(**kwargs))
            else:
                def wrapper(**kwargs):
                    return m(**kwargs)

            wrapper.__name__ = m.__name__
            wrapper.__doc__ = m.__doc__
            return wrapper

        # Register as MCP tool
        tool_func = make_wrapper(method)
        mcp.tool()(tool_func)


# register_class_methods(WiFi, async_methods=False)
# register_class_methods(Bluetooth, async_methods=True)

# Manual test
@mcp.tool()
def network_scan_arp(subnet: str = "192.168.1.0/24"):
    """Scan local network using ARP to find all active devices"""
    return WiFi.network_scan_arp(subnet=subnet)


if __name__ == "__main__":
    print("\n" + "="*60)
    print("Yoda MCP Server Starting...")
    print("="*60)
    print(f"Server URL: http://localhost:8000/sse")
    print("="*60 + "\n")

    mcp.run(transport='sse')
