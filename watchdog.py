"""
Watchdog v2 — Zero-cost infrastructure monitor
Uses Ollama (local) for anomaly analysis.
Reports via Supabase public_* RPC functions (no auth needed).
AutoHeal reads from Supabase and fixes. Manus can also POST alerts.
"""
import asyncio
import json
import os
import logging
import httpx
from datetime import datetime, timezone

COOLIFY_URL    = os.environ.get("COOLIFY_URL", "").rstrip("/")
COOLIFY_TOKEN  = os.environ.get("COOLIFY_TOKEN", "")
SUPABASE_URL   = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY   = os.environ.get("SUPABASE_KEY", "")  # any valid key for this project
OLLAMA_URL     = os.environ.get("OLLAMA_URL", "http://ollama:11434")
OLLAMA_MODEL   = os.environ.get("OLLAMA_MODEL", "qwen2.5:0.5b")
CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", "60"))

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [WATCHDOG] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("watchdog")

last_seen: dict[str, str] = {}
alert_cooldown: dict[str, float] = {}
COOLDOWN_SECONDS = 600


# ── Coolify ────────────────────────────────────────────────────────────────────
async def get_apps() -> list[dict]:
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.get(
            f"{COOLIFY_URL}/api/v1/applications",
            headers={"Authorization": f"Bearer {COOLIFY_TOKEN}"}
        )
        r.raise_for_status()
        return [{
            "uuid": a["uuid"], "name": a["name"],
            "status": a.get("status",""),
            "restarts": a.get("restart_count", 0),
        } for a in r.json()]


# ── Supabase via public RPC (no service_role needed) ──────────────────────────
def sb_headers():
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
    }

async def rpc(fn: str, params: dict) -> any:
    """Call a Supabase SECURITY DEFINER function – works with anon key."""
    if not SUPABASE_URL or not SUPABASE_KEY:
        return None
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                f"{SUPABASE_URL}/rest/v1/rpc/{fn}",
                headers=sb_headers(),
                json=params
            )
            if r.status_code == 200:
                return r.json()
            log.warning(f"RPC {fn} → {r.status_code}: {r.text[:100]}")
            return None
    except Exception as ex:
        log.warning(f"RPC {fn} failed: {ex}")
        return None

async def save_snapshot(app: dict):
    await rpc("public_save_snapshot", {
        "p_uuid": app["uuid"],
        "p_name": app["name"],
        "p_status": app["status"],
        "p_restarts": app["restarts"],
    })

async def create_alert(app: dict, severity: str, message: str) -> bool:
    result = await rpc("public_report_alert", {
        "p_app_uuid": app["uuid"],
        "p_app_name": app["name"],
        "p_status": app["status"],
        "p_source": "watchdog",
        "p_severity": severity,
        "p_message": message,
    })
    return result is not None and result != -1


# ── Ollama ─────────────────────────────────────────────────────────────────────
async def ollama_available() -> bool:
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{OLLAMA_URL}/api/tags")
            return r.status_code == 200
    except Exception:
        return False

async def ollama_analyze(broken: list[dict]) -> dict[str, dict]:
    summary = "\n".join([f"- {a['name']}: {a['status']} (restarts:{a['restarts']})"
                         for a in broken])
    prompt = f"""Analyze broken apps and return ONLY JSON array:
{summary}

[{{"app":"name","severity":"warning|critical","likely_cause":"one sentence"}}]
critical = crash-looping or core service down. warning = single exit."""

    try:
        async with httpx.AsyncClient(timeout=25) as c:
            r = await c.post(f"{OLLAMA_URL}/api/generate", json={
                "model": OLLAMA_MODEL, "prompt": prompt,
                "stream": False, "options": {"temperature": 0.1, "num_predict": 300}
            })
            if r.status_code == 200:
                raw = r.json().get("response","")
                start, end = raw.find("["), raw.rfind("]")+1
                if start >= 0 and end > start:
                    items = json.loads(raw[start:end])
                    return {i.get("app",""): i for i in items}
    except Exception as ex:
        log.warning(f"Ollama: {ex}")
    return {}

def rule_severity(app: dict) -> tuple[str,str]:
    s, r = app["status"], app["restarts"]
    if "restarting" in s: return "critical", f"Crash-looping ({r} restarts)"
    if "exited" in s and r > 5: return "critical", f"Repeated crashes ({r} restarts)"
    if "exited" in s and r > 0: return "warning", f"Exited ({r} restarts)"
    return "warning", f"Exited unexpectedly"


# ── Main loop ──────────────────────────────────────────────────────────────────
async def check_cycle():
    now = datetime.now(timezone.utc).timestamp()

    try:
        apps = await get_apps()
    except Exception as ex:
        log.error(f"Coolify error: {ex}")
        return

    broken  = [a for a in apps if "exited" in a["status"] or "restarting" in a["status"]]
    healthy = [a for a in apps if "running" in a["status"]]

    log.info(f"📊 {len(healthy)} healthy | {len(broken)} broken | {len(apps)} total")

    # Reset cooldowns for recovered apps
    for a in healthy:
        if a["uuid"] in alert_cooldown:
            log.info(f"[{a['name']}] ✅ Recovered")
            del alert_cooldown[a["uuid"]]
        last_seen[a["uuid"]] = a["status"]

    # Snapshots (fire-and-forget for all apps)
    for app in apps:
        asyncio.create_task(save_snapshot(app))

    if not broken:
        return

    # Detect newly broken or persistent
    to_alert = []
    for app in broken:
        prev = last_seen.get(app["uuid"],"")
        is_new = prev != app["status"]
        last_seen[app["uuid"]] = app["status"]
        last_alert = alert_cooldown.get(app["uuid"], 0)
        in_cooldown = now - last_alert < COOLDOWN_SECONDS
        if is_new or not in_cooldown:
            to_alert.append(app)

    if not to_alert:
        log.info("All broken apps in cooldown, no new alerts")
        return

    # Ollama analysis
    ollama_ok = await ollama_available()
    ollama_results = {}
    if ollama_ok and to_alert:
        log.info(f"🤖 Asking Ollama ({OLLAMA_MODEL}) about {len(to_alert)} apps...")
        ollama_results = await ollama_analyze(to_alert)
    else:
        log.info("Using rule-based detection (Ollama unavailable)")

    # Create alerts
    for app in to_alert:
        last_alert = alert_cooldown.get(app["uuid"], 0)
        if now - last_alert < COOLDOWN_SECONDS:
            continue

        if app["name"] in ollama_results:
            item = ollama_results[app["name"]]
            severity = item.get("severity","warning")
            message  = item.get("likely_cause","Unknown")
        else:
            severity, message = rule_severity(app)

        created = await create_alert(app, severity, message)
        if created:
            alert_cooldown[app["uuid"]] = now
            log.info(f"🚨 Alert: [{app['name']}] {severity} – {message}")
        else:
            log.info(f"[{app['name']}] Duplicate alert skipped")


async def main():
    log.info("🛡️  Watchdog v2 starting")
    log.info(f"   Coolify:  {COOLIFY_URL or 'NOT SET'}")
    log.info(f"   Supabase: {SUPABASE_URL[:40] if SUPABASE_URL else 'NOT SET'}...")
    log.info(f"   Ollama:   {OLLAMA_URL} ({OLLAMA_MODEL})")
    log.info(f"   Interval: {CHECK_INTERVAL}s")
    log.info(f"   Auth:     public_* RPC functions (anon key)")

    # Try pulling Ollama model
    if await ollama_available():
        log.info(f"✅ Ollama available, ensuring {OLLAMA_MODEL}...")
        try:
            async with httpx.AsyncClient(timeout=120) as c:
                await c.post(f"{OLLAMA_URL}/api/pull",
                             json={"name": OLLAMA_MODEL, "stream": False})
        except Exception as ex:
            log.warning(f"Ollama pull: {ex}")
    else:
        log.warning("⚠️  Ollama not reachable, using rule-based fallback")

    while True:
        log.info(f"--- {datetime.now().strftime('%H:%M:%S')} ---")
        try:
            await check_cycle()
        except Exception as ex:
            log.error(f"Cycle error: {ex}")
        log.info(f"Sleeping {CHECK_INTERVAL}s")
        await asyncio.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    asyncio.run(main())
