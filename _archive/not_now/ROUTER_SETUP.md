# Router API Deployment

## 1. Install Python on Router

```bash
ssh root@192.168.8.1

opkg update
opkg install python3 python3-pip
```

## 2. Transfer Script

```bash
# From your Mac
scp router_api.py root@192.168.8.1:/root/
```

## 3. Set API Key

```bash
# On router
export ROUTER_API_KEY="your-secret-key-here"
echo 'export ROUTER_API_KEY="your-secret-key-here"' >> /etc/profile
```

## 4. Run API Server

```bash
# Test run
python3 /root/router_api.py

# Run in background
nohup python3 /root/router_api.py > /tmp/router_api.log 2>&1 &
```

## 5. Make it Persistent (Optional)

Create `/etc/init.d/router_api`:

```bash
#!/bin/sh /etc/rc.common
START=99
STOP=10

start() {
    export ROUTER_API_KEY="your-secret-key-here"
    python3 /root/router_api.py > /tmp/router_api.log 2>&1 &
    echo $! > /var/run/router_api.pid
}

stop() {
    kill $(cat /var/run/router_api.pid)
}
```

Enable:
```bash
chmod +x /etc/init.d/router_api
/etc/init.d/router_api enable
/etc/init.d/router_api start
```

## 6. Test from Mac

```bash
# Set API key
export ROUTER_API_KEY="your-secret-key-here"
export ROUTER_API_URL="http://192.168.8.1:8888"

# Test
python3 router_client.py
```

## 7. Use in MCP Server

```python
from router_client import RouterClient

client = RouterClient()
devices = client.get_devices()
```
