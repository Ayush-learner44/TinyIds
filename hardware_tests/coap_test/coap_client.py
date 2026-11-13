"""CoAP client for the NodeMCU CoAP server.

Usage:
  python coap_client.py <nodemcu-ip>              ask for /stats every 2 s (Ctrl+C to stop)
  python coap_client.py <nodemcu-ip> led on       switch the NodeMCU's blue LED on
  python coap_client.py <nodemcu-ip> led off      switch it off

The NodeMCU prints its IP in the Serial Monitor after it joins Wi-Fi.
"""
import asyncio
import sys
from datetime import datetime

from aiocoap import GET, PUT, Context, Message


async def request(ctx, code, uri, payload=b""):
    msg = Message(code=code, uri=uri, payload=payload)
    try:
        resp = await asyncio.wait_for(ctx.request(msg).response, timeout=5)
        return f"{resp.code}  {resp.payload.decode()}"
    except asyncio.TimeoutError:
        return "no answer (timeout): wrong IP, board off, or network blocks UDP 5683"
    except Exception as e:  # e.g. network unreachable
        return f"error: {e}"


async def main():
    if len(sys.argv) < 2:
        print(__doc__)
        return
    ip = sys.argv[1]
    ctx = await Context.create_client_context()

    if len(sys.argv) >= 4 and sys.argv[2] == "led":
        print(await request(ctx, PUT, f"coap://{ip}/led", sys.argv[3].encode()))
        return

    print(f"Polling coap://{ip}/stats every 2 s (Ctrl+C to stop)")
    while True:
        now = datetime.now().strftime("%H:%M:%S")
        print(now, await request(ctx, GET, f"coap://{ip}/stats"))
        await asyncio.sleep(2)


try:
    asyncio.run(main())
except KeyboardInterrupt:
    print("\nStopped.")
