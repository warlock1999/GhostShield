import os
import random
import base64
import asyncio
import aiohttp
from aiohttp import web

# --- CONFIGURATION ---
BIND_IP = "0.0.0.0" 
BIND_PORT = 8443

# SECRETS (Loaded from Environment)
BOT_TOKEN = os.environ.get("BOT_TOKEN")
ADMIN_ID = os.environ.get("ADMIN_ID")
SECRET_PATH = os.environ.get("SECRET_PATH", "dns-query")

# --- THE GHOST ARRAY ---
UPSTREAMS = [
    "https://cloudflare-dns.com/dns-query",       # Cloudflare
    "https://dns.quad9.net/dns-query",            # Quad9
    "https://doh.mullvad.net/dns-query",          # Mullvad
    "https://dns.adguard-dns.com/dns-query",      # AdGuard
    "https://dns.nextdns.io",                     # NextDNS
    "https://freedns.controld.com/p0"             # ControlD
]

# --- BACKGROUND LOGGER ---
async def log_to_telegram(session, domain, provider):
    """Sends logs silently to Telegram without slowing down DNS."""
    try:
        # Filter out junk/empty logs
        if not domain or len(domain) < 3: return
        
        text = f"🔍 {domain}\n➡️ {provider.split('/')[2]}"
        url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        payload = {"chat_id": ADMIN_ID, "text": text, "disable_notification": True}
        
        async with session.post(url, json=payload) as resp:
            pass
    except Exception as e:
        print(f"Log Error: {e}")

# --- DNS ENGINE ---
async def forward_query(query_data, content_type="application/dns-message"):
    """Forwards binary DNS packet to random upstream."""
    upstream = random.choice(UPSTREAMS)
    headers = {"Accept": "application/dns-message", "Content-Type": content_type}

    async with aiohttp.ClientSession() as session:
        try:
            async with session.post(upstream, data=query_data, headers=headers, timeout=2.0) as resp:
                if resp.status == 200:
                    return await resp.read(), 200, upstream
                return None, resp.status, upstream
        except:
            return None, 500, upstream

async def handle_doh(request):
    # 1. SECURITY CHECK
    if SECRET_PATH not in request.path:
        return web.Response(status=403, text="⛔ Access Denied")

    # 2. PARSE REQUEST
    query_data = None
    if request.method == "POST":
        query_data = await request.read()
    elif request.method == "GET":
        dns_base64 = request.query.get("dns")
        if dns_base64:
            try:
                padding = '=' * (-len(dns_base64) % 4)
                query_data = base64.urlsafe_b64decode(dns_base64 + padding)
            except: pass

    if not query_data:
        return web.Response(status=400, text="Bad Request")

    # 3. EXECUTE DNS (Speed Critical)
    response_data, status, provider = await forward_query(query_data)

    # 4. LOGGING (Background Task)
    try:
        # Attempt to extract readable domain from binary packet
        clean_bytes = bytes([b for b in query_data[12:] if 32 < b < 127])
        domain_log = clean_bytes.decode('utf-8')
    except: 
        domain_log = "Encrypted-Packet"

    if response_data:
        # Fire-and-forget log
        asyncio.create_task(log_to_telegram(aiohttp.ClientSession(), domain_log, provider))
        return web.Response(body=response_data, status=status, content_type="application/dns-message")

    return web.Response(status=502)

# --- STARTUP ---
app = web.Application()
app.router.add_route('*', '/{tail:.*}', handle_doh)

if __name__ == "__main__":
    print(f"🚀 GhostShield Active. Port: {BIND_PORT}")
    web.run_app(app, host=BIND_IP, port=BIND_PORT, print=None)
