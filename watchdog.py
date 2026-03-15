"""
Watchdog — Zero-cost infrastructure monitor
Uses Ollama (local open-source model) for anomaly analysis.
Reports to Supabase. AutoHeal reads from Supabase and fixes.
Manus can also POST to Supabase to trigger AutoHeal.
"""
import asyncio
import json
import os
import logging
import httpx
from datetime import datetime, timezone

# ── Config ─────────────────────────────────────────────────────────────────────
COOLIFY_URL    = os.environ.get("COOLIFY_URL", "").rstrip("/")
COOLIFY_TOKEN  = os.environ.get("COOLIFY_TOKEN", "")
SUPABASE_URL   = os.environ.get("SUPABASE_URL", "")
SUPABASE_KEY   = os.environ.get("SUPABASE_KEY", "")  # service_role key
OLLAMA_URL     = os.environ.get("OLLAMA_URL", "http://ollama:11434")  # internal docker network
OLLAMA_MODEL   = os.environ.get("OLLAMA_MODEL", "qwen2.5:0.5b")  # tiny & fast, ~400MB
CHECK_INTERVAL = int(os.environ.get("CHECK_INTERVAL", "60"))  # 1 min

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [WATCHDOG] %(message)s",
    datefmt="%H:%M:%S"
)
log = logging.getLogger("watchdog")

# Track seen states to detect changes
last_seen: dict[str, str] = {}
alert_cooldown: dict[str, float] = {}
COOLDOWN_SECONDS = 600  # 10 min between alerts for same app


# ── Coolify ────────────────────────────────────────────────────────────────────
async def get_apps() -> list[dict]:
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.get(
            f"{COOLIFY_URL}/api/v1/applications",
            headers={"Authorization": f"Bearer {COOLIFY_TOKEN}"}
        )
        r.raise_for_status()
        return [{
            "uuid": a["uuid"],
            "name": a["name"],
            "status": a.get("status", ""),
            "restarts": a.get("restart_count", 0),
            "repo": a.get("git_repository", ""),
        } for a in r.json()]


# ── Supabase ───────────────────────────────────────────────────────────────────
def sb_headers():
    return {
        "apikey": SUPABASE_KEY,
        "Authorization": f"Bearer {SUPABASE_KEY}",
        "Content-Type": "application/json",
        "Prefer": "return=minimal"
    }

async def save_snapshot(app: dict):
    async with httpx.AsyncClient(timeout=10) as c:
        await c.post(
            f"{SUPABASE_URL}/rest/v1/app_health_snapshots",
            headers=sb_headers(),
            json={
                "app_uuid": app["uuid"],
                "app_name": app["name"],
                "status": app["status"],
                "restarts": app["restarts"],
            }
        )

async def create_alert(app: dict, severity: str, message: str, logs: str = "") -> bool:
    """Insert alert via RPC function (deduplicates within 10 min)."""
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.post(
                f"{SUPABASE_URL}/rest/v1/rpc/report_alert",
                headers=sb_headers(),
                json={
                    "p_app_uuid": app["uuid"],
                    "p_app_name": app["name"],
                    "p_status": app["status"],
                    "p_source": "watchdog",
                    "p_severity": severity,
                    "p_message": message,
                    "p_logs": logs[:3000] if logs else None,
                }
            )
            result = r.json()
            return result != -1  # -1 = duplicate, already have active alert
    except Exception as ex:
        log.error(f"Supabase alert failed: {ex}")
        return False

async def get_unhandled_alerts() -> list[dict]:
    """AutoHeal polls this to find work."""
    async with httpx.AsyncClient(timeout=10) as c:
        r = await c.get(
            f"{SUPABASE_URL}/rest/v1/autoheal_alerts",
            headers=sb_headers(),
            params={"handled": "eq.false", "order": "created_at.desc", "limit": "10"}
        )
        return r.json() if r.status_code == 200 else []


# ── Ollama anomaly detection ───────────────────────────────────────────────────
async def ollama_available() -> bool:
    try:
        async with httpx.AsyncClient(timeout=5) as c:
            r = await c.get(f"{OLLAMA_URL}/api/tags")
            return r.status_code == 200
    except Exception:
        return False

async def ollama_analyze(apps: list[dict], broken: list[dict]) -> str:
    """Use tiny local model to detect anomalies. Free, no API cost."""
    if not broken:
        return ""

    summary = "\n".join([
        f"- {a['name']}: {a['status']} (restarts: {a['restarts']})"
        for a in broken
    ])

    prompt = f"""You are a DevOps monitoring agent. Analyze these broken applications:

{summary}

Total: {len(apps)} apps, {len(broken)} broken.

Respond with ONLY a JSON array of issues, one per broken app:
[{{"app": "name", "severity": "warning|critical", "likely_cause": "one sentence"}}]

critical = exited + high restarts or core service down
warning = exited but low restarts"""

    try:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(
                f"{OLLAMA_URL}/api/generate",
                json={
                    "model": OLLAMA_MODEL,
                    "prompt": prompt,
                    "stream": False,
                    "options": {"temperature": 0.1, "num_predict": 300}
                }
            )
            if r.status_code == 200:
                return r.json().get("response", "")
    except Exception as ex:
        log.warning(f"Ollama unavailable: {ex}")
    return ""


def parse_ollama_response(raw: str) -> list[dict]:
    """Parse Ollama JSON response, handle malformed output."""
    if not raw:
        return []
    try:
        # Find JSON array in response
        start = raw.find("[")
        end = raw.rfind("]") + 1
        if start >= 0 and end > start:
            return json.loads(raw[start:end])
    except Exception:
        pass
    return []


def rule_based_severity(app: dict) -> tuple[str, str]:
    """Fallback when Ollama is unavailable. Pure logic, zero cost."""
    status = app["status"]
    restarts = app["restarts"]

    if "exited" in status and restarts > 5:
        return "critical", f"App crash-looping ({restarts} restarts)"
    elif "exited" in status and restarts > 0:
        return "warning", f"App exited unexpectedly ({restarts} restarts)"
    elif "exited" in status:
        return "warning", "App exited, no restarts recorded"
    elif "restarting" in status:
        return "critical", "App is actively restarting (crash loop)"
    return "info", f"Unhealthy status: {status}"


# ── Main monitor loop ──────────────────────────────────────────────────────────
async def check_cycle():
    now = datetime.now(timezone.utc).timestamp()

    # 1. Get all apps
    try:
        apps = await get_apps()
    except Exception as ex:
        log.error(f"Coolify API error: {ex}")
        return

    broken  = [a for a in apps if "exited" in a["status"] or "restarting" in a["status"]]
    healthy = [a for a in apps if "running" in a["status"]]

    log.info(f"📊 {len(healthy)} healthy | {len(broken)} broken | {len(apps)} total")

    # 2. Save snapshots for all (async, fire-and-forget)
    for app in apps:
        asyncio.create_task(save_snapshot(app))

    if not broken:
        # Clear cooldowns for recovered apps
        for app in healthy:
            alert_cooldown.pop(app["uuid"], None)
        return

    # 3. Detect NEW problems (status changed since last check)
    newly_broken = []
    for app in broken:
        prev = last_seen.get(app["uuid"], "")
        if prev != app["status"]:
            newly_broken.append(app)
            log.info(f"[{app['name']}] Status change: {prev or 'unknown'} → {app['status']}")
        last_seen[app["uuid"]] = app["status"]

    # Also include persistent broken (unchanged but still broken after cooldown)
    persistent = [
        a for a in broken
        if a not in newly_broken
        and now - alert_cooldown.get(a["uuid"], 0) > COOLDOWN_SECONDS
    ]

    to_alert = newly_broken + persistent
    if not to_alert:
        log.info("No new alerts needed (cooldown active)")
        return

    # 4. Try Ollama for smart analysis (free, local)
    ollama_ok = await ollama_available()
    ollama_results = {}

    if ollama_ok:
        log.info(f"🤖 Asking Ollama ({OLLAMA_MODEL}) to analyze {len(to_alert)} apps...")
        raw = await ollama_analyze(apps, to_alert)
        parsed = parse_ollama_response(raw)
        for item in parsed:
            ollama_results[item.get("app", "")] = item
        log.info(f"Ollama analyzed {len(ollama_results)} apps")
    else:
        log.info("Ollama unavailable, using rule-based detection")

    # 5. Create alerts in Supabase
    for app in to_alert:
        # Check cooldown
        last_alert = alert_cooldown.get(app["uuid"], 0)
        if now - last_alert < COOLDOWN_SECONDS:
            continue

        # Get severity + message
        if app["name"] in ollama_results:
            item = ollama_results[app["name"]]
            severity = item.get("severity", "warning")
            message = item.get("likely_cause", "Unknown issue")
        else:
            severity, message = rule_based_severity(app)

        created = await create_alert(app, severity, message)
        if created:
            alert_cooldown[app["uuid"]] = now
            log.info(f"🚨 Alert: [{app['name']}] {severity} – {message}")
        else:
            log.info(f"[{app['name']}] Alert skipped (duplicate)")


async def main():
    log.info("🛡️  Watchdog starting")
    log.info(f"   Coolify:  {COOLIFY_URL or 'NOT SET'}")
    log.info(f"   Supabase: {SUPABASE_URL[:40] if SUPABASE_URL else 'NOT SET'}...")
    log.info(f"   Ollama:   {OLLAMA_URL} ({OLLAMA_MODEL})")
    log.info(f"   Interval: {CHECK_INTERVAL}s")
    log.info(f"   Strategy: Ollama first → rule-based fallback")

    # Try to pull Ollama model on startup
    ollama_ok = await ollama_available()
    if ollama_ok:
        log.info(f"✅ Ollama available, pulling {OLLAMA_MODEL} if needed...")
        try:
            async with httpx.AsyncClient(timeout=120) as c:
                await c.post(f"{OLLAMA_URL}/api/pull",
                             json={"name": OLLAMA_MODEL, "stream": False})
            log.info(f"✅ Model {OLLAMA_MODEL} ready")
        except Exception as ex:
            log.warning(f"Model pull failed: {ex} (may already exist)")
    else:
        log.warning("⚠️  Ollama not reachable at startup, will retry each cycle")

    while True:
        try:
            await check_cycle()
        except Exception as ex:
            log.error(f"Cycle error: {ex}")
        await asyncio.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    asyncio.run(main())
