#!/usr/bin/env python3
from curl_cffi import requests as cffi_requests
import requests as stdlib_requests
import re, urllib.parse, hashlib, random, traceback, uuid, json, time, base64, math, io, struct
from collections import deque
from Crypto.Cipher import AES
from Crypto.Util import Counter
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import numpy as np

__version__ = "1.0.0"
CHROME_VERSIONS = [120, 123, 124, 131, 136, 142]
IMPERSONATE_MAP = {
    120: "chrome120", 123: "chrome123", 124: "chrome124",
    131: "chrome131", 136: "chrome136", 142: "chrome142",
}
SCREEN_RESOLUTIONS = [
    "1920x1080", "1366x768", "1536x864", "1440x900", "1280x720",
    "1600x900", "2560x1440", "1920x1200",
]
PLATFORMS = {
    "Windows": {
        "ua":  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36",
        "nav": "Win32",
        "sec": '"Windows"',
    },
    "Linux": {
        "ua":  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36",
        "nav": "Linux x86_64",
        "sec": '"Linux"',
    },
    "macOS": {
        "ua":  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/{v}.0.0.0 Safari/537.36",
        "nav": "MacIntel",
        "sec": '"macOS"',
    },
}
LANGUAGES = [
    "en-US,en;q=0.9",
    "en-GB,en;q=0.8",
    "en-US,en;q=0.9,es;q=0.7",
]

def _random_fingerprint():
    plat_name = random.choices(["Windows", "macOS", "Linux"], weights=[72, 20, 8])[0]
    plat = PLATFORMS[plat_name]
    v = random.choices(CHROME_VERSIONS, weights=[3, 6, 10, 18, 24, 39])[0]
    res = random.choices(SCREEN_RESOLUTIONS, weights=[35, 20, 15, 10, 8, 6, 4, 2])[0]
    brand_orders = [
        f'"Chromium";v="{v}", "Not:A-Brand";v="24", "Google Chrome";v="{v}"',
        f'"Google Chrome";v="{v}", "Chromium";v="{v}", "Not:A-Brand";v="24"',
    ]
    return {
        "user_agent":         plat["ua"].format(v=v),
        "platform":           plat_name,
        "navigator_platform": plat["nav"],
        "sec_ch_ua":          random.choice(brand_orders),
        "sec_ch_ua_platform": plat["sec"],
        "language":           random.choice(LANGUAGES),
        "resolution":         res,
        "chrome_version":     v,
    }

def _build_session(fp):
    session = cffi_requests.Session(impersonate=IMPERSONATE_MAP[fp["chrome_version"]])
    session.headers.update({
        "User-Agent":                fp["user_agent"],
        "Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
        "Accept-Language":           fp["language"],
        "Accept-Encoding":           "gzip, deflate, br, zstd",
        "Connection":                "keep-alive",
        "Sec-CH-UA":                 fp["sec_ch_ua"],
        "Sec-CH-UA-Mobile":          "?0",
        "Sec-CH-UA-Platform":        fp["sec_ch_ua_platform"],
        "Sec-Fetch-Dest":            "document",
        "Sec-Fetch-Mode":            "navigate",
        "Sec-Fetch-Site":            "none",
        "Sec-Fetch-User":            "?1",
        "Upgrade-Insecure-Requests": "1",
    })
    return session

def _get_param(url, param):
    parsed = urllib.parse.urlparse(url)
    params = urllib.parse.parse_qs(parsed.query)
    values = params.get(param, [])
    return values[0] if values else None

def solve_captcha():
    """Solve CAPTCHA via tirex-delta API - FAST!"""
    for attempt in range(37):
        try:
            resp = stdlib_requests.get("https://tirex-delta.vercel.app/api/solve", timeout=15).json()
            if resp.get("success") and resp.get("token"):
                return resp["token"]
        except Exception as e:
            pass
    return None

def generate_stream(ticket: str, screen_width=1920, screen_height=1080) -> str:
    try:
        now       = int(time.time() * 1000)
        is_mobile = random.random() < 0.12
        events    = []

        def ev(typ, x, y, tag, t):
            events.append({"event": typ, "data": {
                "x": int(max(0, min(screen_width,  x))),
                "y": int(max(0, min(screen_height, y))),
                "target": tag, "time": int(t),
            }})

        btn_x = int(screen_width  * 0.50) + random.randint(-70, 70)
        btn_y = int(screen_height * 0.44) + random.randint(-50, 50)

        if is_mobile:
            t = now - random.randint(5000, 14000)
            for _ in range(random.randint(0, 2)):
                t += random.randint(1000, 4000)
                px = random.randint(int(screen_width * 0.15), int(screen_width * 0.85))
                py = random.randint(int(screen_height * 0.15), int(screen_height * 0.75))
                ev(1, px, py, random.choice(["BUTTON", "A", "DIV"]), t)

            t_click = now - random.randint(120, 600)
            ev(1, btn_x + random.randint(-5, 5), btn_y + random.randint(-5, 5), "BUTTON", t_click)
            t_touch = t_click - random.randint(40, 140)
            ev(2, btn_x + random.randint(-8, 8), btn_y + random.randint(-8, 8), "BUTTON", t_touch)

        else:
            cx = random.randint(int(screen_width  * 0.10), int(screen_width  * 0.90))
            cy = random.randint(int(screen_height * 0.10), int(screen_height * 0.75))
            t  = now - random.randint(5000, 14000)

            IDLE_TAGS     = ["BODY", "DIV", "P", "H1", "H2", "SPAN"]
            APPROACH_TAGS = ["DIV", "SPAN", "BUTTON"]

            for _ in range(random.randint(2, 5)):
                t  += random.randint(180, 1400)
                cx  = cx + random.randint(-280, 280)
                cy  = cy + random.randint(-180, 180)
                ev(0, cx, cy, random.choice(IDLE_TAGS), t)

            n_app = random.randint(2, 4)
            for i in range(n_app):
                t   += random.randint(50, 320)
                frac = (i + 1) / n_app * random.uniform(0.65, 1.0)
                cx   = cx + (btn_x - cx) * frac + random.randint(-6, 6)
                cy   = cy + (btn_y - cy) * frac + random.randint(-6, 6)
                tag  = "BUTTON" if i == n_app - 1 else random.choice(APPROACH_TAGS)
                ev(0, cx, cy, tag, t)

            t_prior = now - random.randint(6000, 14000)
            for _ in range(random.randint(0, 3)):
                t_prior += random.randint(600, 2800)
                px = random.randint(int(screen_width  * 0.20), int(screen_width  * 0.80))
                py = random.randint(int(screen_height * 0.20), int(screen_height * 0.70))
                ev(1, px, py, random.choice(["BUTTON", "A", "DIV", "SPAN"]), t_prior)

            t += random.randint(140, 700)
            t_click = t
            ev(1, btn_x + random.randint(-3, 3), btn_y + random.randint(-3, 3), "BUTTON", t_click)
            t_move = t_click - random.randint(14, 55)
            ev(0, btn_x + random.randint(-6, 6), btn_y + random.randint(-6, 6), "BUTTON", t_move)

        events.append({"event": 5, "data": {"time": now, "length": 0}})

        payload  = json.dumps({"events": events})
        key      = bytes(ord(c) for c in ticket[1:17])
        iv_bytes = bytes(ord(c) for c in ticket[17:33])
        ctr      = Counter.new(128, initial_value=int.from_bytes(iv_bytes, "big"))
        cipher   = AES.new(key, AES.MODE_CTR, counter=ctr)
        return cipher.encrypt(payload.encode("utf-8")).hex()
    except Exception:
        return ""


def getMeta(ticket: str, screen_res: str, user_agent: str, nav_platform: str) -> str:
    try:
        if not ticket or len(ticket) < 32:
            return "empty"
        key      = bytes(ord(c) for c in ticket[0:16])
        iv_bytes = bytes(ord(c) for c in ticket[16:32])
        sw, sh   = int(screen_res.split("x")[0]), int(screen_res.split("x")[1])
        avail_h = sh - random.choices([40, 48, 32, 23], weights=[55, 20, 15, 10])[0]
        plugins_item = [
            {"name": "PDF Viewer",                "filename": "internal-pdf-viewer", "description": "Portable Document Format"},
            {"name": "Chrome PDF Viewer",         "filename": "internal-pdf-viewer", "description": "Portable Document Format"},
            {"name": "Chromium PDF Viewer",       "filename": "internal-pdf-viewer", "description": "Portable Document Format"},
            {"name": "Microsoft Edge PDF Viewer", "filename": "internal-pdf-viewer", "description": "Portable Document Format"},
            {"name": "WebKit built-in PDF",       "filename": "internal-pdf-viewer", "description": "Portable Document Format"},
        ]
        mimetypes_item = [
            {"type": "application/pdf", "description": "Portable Document Format", "suffixes": "pdf"},
            {"type": "text/pdf",        "description": "Portable Document Format", "suffixes": "pdf"},
        ]
        conn = random.choices([
            {"effectiveType": "4g", "downlink": 10,   "rtt": 50},
            {"effectiveType": "4g", "downlink": 5,    "rtt": 75},
            {"effectiveType": "4g", "downlink": 2.5,  "rtt": 100},
            {"effectiveType": "4g", "downlink": 1.25, "rtt": 150},
            {"effectiveType": "3g", "downlink": 0.75, "rtt": 300},
            {"effectiveType": "3g", "downlink": 0.5,  "rtt": 375},
        ], weights=[40, 22, 16, 10, 8, 4])[0]
        hist_len = random.choices([1, 2, 3, 4], weights=[30, 35, 25, 10])[0]
        info = [
            {"name": "screen", "data": {
                "width":       sw,
                "height":      sh,
                "availWidth":  sw,
                "availHeight": avail_h,
                "colorDepth":  24,
                "pixelDepth":  24,
                "orientation": {"type": "landscape-primary", "angle": 0},
            }},
            {"name": "navigator", "data": {
                "userAgent":      user_agent,
                "platform":       nav_platform,
                "maxTouchPoints": 0,
                "plugins":   {"length": len(plugins_item),   "item": plugins_item},
                "mimeTypes": {"length": len(mimetypes_item), "item": mimetypes_item},
            }},
            {"name": "performance", "data": int(time.time() * 1000)},
            {"name": "history",     "data": {"length": hist_len}},
            {"name": "webdriver",   "webdriver": False},
            {"name": "connection",  "data": {**conn, "saveData": False}},
        ]
        payload = json.dumps({"browserInfo": info}, separators=(",", ":"))
        ctr    = Counter.new(128, initial_value=int.from_bytes(iv_bytes, "big"))
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        return cipher.encrypt(payload.encode("utf-8")).hex()
    except Exception:
        return "empty"

def checkKey(ticket, session):
    key = session.get(f"https://auth.platorelay.com/api/session/status?ticket={ticket}").json().get("data", {}).get("key")
    return None if (not key or key == "KEY_NOT_FOUND") else key

def _resolve_service(pref, meta):
    if isinstance(pref, int):
        return pref
    service_bits = (meta.get("activeRevenueProfile") or {}).get("service", 0) or 0
    if service_bits & 1:
        return 1
    if service_bits & 2:
        return 2
    if service_bits & 4:
        return 4
    return 1

def _get_metadata(ticket, session):
    try:
        j = session.get(f"https://auth.platorelay.com/api/session/metadata?ticket={ticket}").json()
        if j.get("success"):
            return j.get("data") or {}
    except Exception:
        pass
    return None

def _bypass_loot(loot_url):
    """Bypass ANY link using 93.115.101.152:13909 API"""
    try:
        r = stdlib_requests.get(
            f"http://93.115.101.152:13909/freeapibypass?url={urllib.parse.quote(loot_url)}",
            timeout=30
        ).json()
        if (r.get("status") == "success" or r.get("success")) and r.get("result"):
            return r["result"]
        print(f"[bypass] {json.dumps(r)}")
    except Exception as e:
        print(f"[✗] bypass error: {e}")
    return None

def _human_delay():
    """Random delay to simulate human behavior - avoids 'too fast' detection"""
    time.sleep(random.uniform(2, 2.5))

def getKey(url, verbose_cb=None, service=None):
    start_time = time.time()
    vcb = verbose_cb or (lambda msg: None)
    
    fp = _random_fingerprint()
    session = _build_session(fp)
    session.headers.update({
        "Accept":           "application/json",
        "X-Client-Name":    "platoboost webclient",
        "X-Client-Version": "5.3.2",
        "Sec-Fetch-Dest":   "empty",
        "Sec-Fetch-Mode":   "cors",
        "Sec-Fetch-Site":   "same-origin",
    })
    session.headers.pop("Sec-Fetch-User", None)
    session.headers.pop("Upgrade-Insecure-Requests", None)

    try:
        ticket     = _get_param(url, "d") or _get_param(url, "ticket")
        hash_param = _get_param(url, "hash")
        screen_res = fp["resolution"]
        sw         = int(screen_res.split("x")[0])
        sh         = int(screen_res.split("x")[1])
        user_agent = fp["user_agent"]
        nav_plat   = fp["navigator_platform"]

        session.headers["Referer"] = f"https://auth.platorelay.com/a?d={ticket}"

        key = checkKey(ticket, session)
        if key:
            elapsed = time.time() - start_time
            vcb(f"✓ Done in {elapsed:.2f}s")
            return key

        vcb("Running bypass...")
        resolved = True
        too_fast_retries = 0

        for _outer in range(30):
            meta = _get_metadata(ticket, session)
            if meta is None:
                print("[!] metadata fetch failed")
                break

            completed   = meta.get("completed", 0)
            total       = (meta.get("activeRevenueProfile") or {}).get("checkpointCount", 0)
            et_on       = meta.get("enableEventTracker", False)
            svc         = _resolve_service(service, meta)

            vcb(f"checkpoint {completed}/{total}")

            if completed >= total:
                break

            step_url = f"https://auth.platorelay.com/api/session/step?ticket={ticket}&service={svc}"
            if hash_param:
                step_url += f"&hash={hash_param}"

            mk = lambda: getMeta(ticket, screen_res, user_agent, nav_plat)
            sk = lambda: generate_stream(ticket, sw, sh) if et_on else ""

            payload = {"captcha": None, "meta": mk(), "stream": sk(), "resolved": resolved}
            resp    = session.put(step_url, json=payload).json()
            loot_url = (resp.get("data") or {}).get("url") if resp.get("success") else None

            if not loot_url:
                msg = (resp.get("data") or {}).get("message") or resp.get("message") or ""
                msg_lower = msg.lower()
                
                # Detect "too fast" and auto-retry with longer delay
                if "too fast" in msg_lower or "slow down" in msg_lower:
                    too_fast_retries += 1
                    wait_time = 3 + too_fast_retries * 2
                    print(f"[!] too fast detected, waiting {wait_time}s... (retry #{too_fast_retries})")
                    time.sleep(wait_time)
                    continue
                
                too_fast_retries = 0
                print(f"[step] {msg or json.dumps(resp)}")

                vcb("Solving CAPTCHA...")
                cap = solve_captcha()
                if not cap:
                    print("[!] captcha failed, retrying...")
                    _human_delay()
                    continue

                print(f"[captcha] {cap[:24]}...")
                payload["captcha"] = cap
                payload["stream"]  = sk()
                payload["meta"]    = mk()
                resp     = session.put(step_url, json=payload).json()
                loot_url = (resp.get("data") or {}).get("url") if resp.get("success") else None

            if not loot_url:
                print(f"[step] no url — {json.dumps(resp)}")
                key = checkKey(ticket, session)
                if key:
                    elapsed = time.time() - start_time
                    vcb(f"✓ Done in {elapsed:.2f}s")
                    return key
                _human_delay()
                continue

            vcb("Bypassing ad link...")
            print(f"[loot] {loot_url[:80]}...")

            result = _bypass_loot(loot_url)
            if not result:
                print("[!] loot bypass failed, retrying...")
                _human_delay()
                continue

            print(f"[solved] {result[:80]}...")

            new_ticket = _get_param(result, "d") or _get_param(result, "ticket")
            if new_ticket:
                ticket     = new_ticket
                hash_param = _get_param(result, "hash")
                session.headers["Referer"] = f"https://auth.platorelay.com/a?d={ticket}"

            for _visit in (loot_url, result):
                try:
                    session.get(_visit, timeout=6)
                except Exception:
                    pass

            # Human-like delay between checkpoints to avoid "too fast" detection
            _human_delay()

        # Ensure we've completed all checkpoints before unlocking
        meta = _get_metadata(ticket, session) or {}
        completed = meta.get("completed", 0)
        total = (meta.get("activeRevenueProfile") or {}).get("checkpointCount", 0)
        
        if completed < total:
            vcb(f"Waiting for checkpoints to sync ({completed}/{total})...")
            time.sleep(2)

        vcb("Unlocking...")
        et_on    = meta.get("enableEventTracker", False)
        svc      = _resolve_service(service, meta)
        step_url = f"https://auth.platorelay.com/api/session/step?ticket={ticket}&service={svc}"
        if hash_param:
            step_url += f"&hash={hash_param}"

        unlock_payload = {
            "captcha":  None,
            "meta":     getMeta(ticket, screen_res, user_agent, nav_plat),
            "stream":   generate_stream(ticket, sw, sh) if et_on else "",
            "resolved": resolved,
        }
        
        unlock_resp = session.put(step_url, json=unlock_payload).json()
        
        if unlock_resp.get("success"):
            print(f"[unlock] ✓ Success — {(unlock_resp.get('data') or {}).get('url', '')}")
        else:

            msg = (unlock_resp.get("data") or {}).get("message") or unlock_resp.get("message") or ""
            print(f"[unlock] Attempt 1 failed: {msg}")
            print(f"[unlock] Retrying in 3s...")
            time.sleep(3)
            
            unlock_resp = session.put(step_url, json=unlock_payload).json()
            
            if unlock_resp.get("success"):
                print(f"[unlock] ✓ Success (retry) — {(unlock_resp.get('data') or {}).get('url', '')}")
            else:
                msg = (unlock_resp.get("data") or {}).get("message") or unlock_resp.get("message") or ""
                print(f"[unlock] ✗ All attempts failed: {msg}")

        vcb("Fetching key...")
        key = checkKey(ticket, session)
        if key:
            elapsed = time.time() - start_time
            vcb(f"✓ Done in {elapsed:.2f}s")
            return key

        time.sleep(2)
        key = checkKey(ticket, session)
        if key:
            elapsed = time.time() - start_time
            vcb(f"✓ Done in {elapsed:.2f}s")
            return key

        elapsed = time.time() - start_time
        return f"bypass fail! ({elapsed:.2f}s)"

    except Exception:
        elapsed = time.time() - start_time
        print(f"[!] {traceback.format_exc()}")
        return f"bypass fail! ({elapsed:.2f}s)"
    finally:
        try:
            session.close()
        except Exception:
            pass

def get_token():
    return solve_captcha()

__all__ = ["getKey", "get_token"]

if __name__ == "__main__":
    url = input("URL: ").strip()
    result = getKey(url, verbose_cb=print)
    if result and not result.startswith("bypass fail"):
        print(f"\n[✓] {result}")
    else:
        print(f"\n[✗] {result}")
    print("\nMade by archivistex")
    print("Discord server(dev): https://discord.gg/4FfnpyPg27")
