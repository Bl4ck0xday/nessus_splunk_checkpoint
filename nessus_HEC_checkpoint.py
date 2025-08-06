import requests, json, os, time, pathlib, sys, urllib3, datetime
from typing import Dict, Any

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ──────────────────── Config file ────────────────────
CONFIG_PATH = pathlib.Path(__file__).with_name("servers.json")
if not CONFIG_PATH.exists():
    sys.exit("[fatal] servers.json not found")

server: Dict[str, Any] = json.loads(CONFIG_PATH.read_text())

# ──────────────────── Splunk settings ────────────────────
spl = server.get("Splunk", {})
required_splunk_keys = ["Address", "Port", "Protocol", "HEC_TOKEN", "Sourcetype", "Host"]
missing = [k for k in required_splunk_keys if k not in spl]
if missing:
    sys.exit(f"[fatal] Missing Splunk config keys: {', '.join(missing)}")

SPLUNK_URL   = f"{spl['Protocol']}://{spl['Address']}:{spl['Port']}"
SPLUNK_HOST  = spl["Host"]
SPLUNK_STYPE = spl["Sourcetype"]
HEC_TOKEN    = spl["HEC_TOKEN"]

# ──────────────────── Nessus settings ────────────────────
nes = server.get("Nessus", {})
NESSUS_BASE  = f"{nes.get('Protocol','https')}://{nes.get('Address')}:{nes.get('Port',8834)}/scans/"
N_ACCESS_KEY = nes.get("AccessKey")
N_SECRET_KEY = nes.get("SecretKey")

if not all([HEC_TOKEN, N_ACCESS_KEY, N_SECRET_KEY]):
    sys.exit("[fatal] Missing credentials (HEC_TOKEN / Nessus keys)")

NESSUS_AUTH = {"X-ApiKeys": f"accessKey={N_ACCESS_KEY}; secretKey={N_SECRET_KEY}"}

# ──────────────────── Checkpoint ────────────────────
CHK_FILE = "checkpoint.json"
checkpoint: Dict[str, Dict[str, list]] = {}
if pathlib.Path(CHK_FILE).exists():
    raw = json.loads(pathlib.Path(CHK_FILE).read_text())
    for k, v in raw.items():
        checkpoint[str(k)] = v if isinstance(v, dict) else {}

def save_chk():
    pathlib.Path(CHK_FILE).write_text(json.dumps(checkpoint))

def plugin_seen(scan: str, host: str, pid: int) -> bool:
    return pid in checkpoint.get(scan, {}).get(host, [])

def mark_plugin(scan: str, host: str, pid: int):
    checkpoint.setdefault(scan, {}).setdefault(host, [])
    if pid not in checkpoint[scan][host]:
        checkpoint[scan][host].append(pid)

def list_scans():
    r = requests.get(NESSUS_BASE, headers=NESSUS_AUTH, verify=False, timeout=60)
    r.raise_for_status()
    return r.json().get("scans", [])

def main():
    for s in list_scans():
        process_scan(s["id"])
    save_chk()

def process_scan(scan_id: int):
    try:
        detail = requests.get(f"{NESSUS_BASE}{scan_id}?limit=2500&includeHostDetailsForHostDiscovery=true", headers=NESSUS_AUTH, verify=False, timeout=120).json()
    except Exception as e:
        print(f"[warn] scan {scan_id} → {e}")
        return

    info = detail.get("info", {})
    if info.get("status") != "completed":
        return

    hist_id = detail.get("history", [])[-1].get("history_id", 0) if detail.get("history") else 0
    s_start = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(info.get("scanner_start", 0)))
    s_end   = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(info.get("scanner_end", 0)))

    for host in detail.get("hosts", []):
        handle_host(scan_id, host, hist_id, s_start, s_end, info.get("status"))

def handle_host(scan_id: int, host_d: Dict[str, Any], hist_id: int, s_start: str, s_end: str, s_status: str):
    host_id = str(host_d["host_id"])
    hostname = host_d.get("hostname", host_id)
    try:
        host_detail = requests.get(f"{NESSUS_BASE}{scan_id}/hosts/{host_id}", headers=NESSUS_AUTH, verify=False, timeout=120).json()
    except Exception as e:
        print(f"[warn] host {host_id} → {e}")
        return

    for vuln in host_detail.get("vulnerabilities", []):
        pid = vuln["plugin_id"]
        if plugin_seen(str(scan_id), host_id, pid):
            continue
        try:
            plugin = requests.get(f"{NESSUS_BASE}{scan_id}/hosts/{host_id}/plugins/{pid}", headers=NESSUS_AUTH, verify=False, timeout=120).json()
        except Exception as e:
            print(f"[warn] plugin {pid} → {e}")
            continue
        event = {
            **vuln, **plugin,
            "hostname": hostname,
            "scanner_start": s_start,
            "scanner_end": s_end,
            "scanner_status": s_status,
            "history_id": hist_id
        }
        send_splunk(event)
        mark_plugin(str(scan_id), host_id, pid)

def send_splunk(event: Dict[str, Any]):
    payload = {
        "sourcetype": SPLUNK_STYPE,
        "host": SPLUNK_HOST,
        "event": event
    }
    try:
        r = requests.post(f"{SPLUNK_URL}/services/collector/event", headers={"Authorization": f"Splunk {HEC_TOKEN}"}, json=payload, verify=False, timeout=15)
        if r.status_code != 200:
            print(f"[error] HEC {r.status_code} – {r.text}")
    except Exception as e:
        print(f"[error] HEC request → {e}")

if __name__ == "__main__":
    main()
