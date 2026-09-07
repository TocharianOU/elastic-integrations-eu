#!/usr/bin/env python3
"""Replay captured OPNsense syslog into Elasticsearch through the installed pipeline.

The capture came from a lab bridge, so the private lab addresses are remapped to
routable ranges and the timestamps spread across the last 24h, which is what makes
the port-over-time heatmap show anything.
"""
import json, os, re, random, ssl, base64, datetime, urllib.request

ES = os.environ["ES_URL"]
AUTH = base64.b64encode(f"{os.environ['ES_USER']}:{os.environ['ES_PASS']}".encode()).decode()
INDEX = "logs-opnsense.log-default"
ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE

# Stand-ins for the lab's 10.99.0.x scanner, with real geography so the map and
# the country column have something to show.
SOURCES = [
    "45.83.64.10", "185.220.101.34", "92.118.39.80", "193.32.162.150",
    "104.244.72.115", "212.70.149.150", "159.223.44.20", "1.15.62.44",
    "80.94.95.226", "141.98.11.30",
]
FIREWALL_WAN = "203.0.113.10"

def weighted_time(now):
    hour = random.choices(range(24),
        weights=[4,3,2,2,1,1,2,4,6,8,9,9,8,8,9,10,9,8,7,6,6,5,4,3])[0]
    base = now - datetime.timedelta(hours=random.randint(0, 23))
    t = base.replace(hour=hour, minute=random.randint(0, 59),
                     second=random.randint(0, 59), microsecond=0)
    return t - datetime.timedelta(days=1) if t > now else t

def main():
    lines = [l for l in open("/data/opnsense/capture/syslog.log", encoding="utf-8",
                             errors="replace").read().splitlines() if "filterlog" in l]
    now = datetime.datetime.now(datetime.timezone.utc)
    docs, seq = [], 0
    while len(docs) < 600:
        raw = random.choice(lines)
        body = raw.split("] ", 1)[-1]
        f = body.split(",")
        if len(f) < 9:
            continue
        src = random.choice(SOURCES)
        body = body.replace("10.99.0.1,", src + ",").replace("10.99.0.10,", FIREWALL_WAN + ",")
        body = body.replace("192.168.1.2,", src + ",").replace("192.168.1.1,", FIREWALL_WAN + ",")
        # vary the destination port so the heatmap has a real spread
        parts = body.split(",")
        if len(parts) > 19 and parts[16] in ("tcp", "udp"):
            parts[19] = str(random.choice(
                [22, 23, 80, 443, 445, 1433, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017, 5900]))
            body = ",".join(parts)
        seq += 1
        ts = weighted_time(now).strftime("%Y-%m-%dT%H:%M:%S+00:00")
        docs.append(f'<134>1 {ts} OPNsense.localdomain filterlog 54555 - '
                    f'[meta sequenceId="{seq}"] {body}')

    lines_out = []
    for d in docs:
        lines_out.append(json.dumps({"create": {}}))
        lines_out.append(json.dumps({
            "message": d, "tags": ["opnsense", "forwarded"],
            "data_stream": {"type": "logs", "dataset": "opnsense.log", "namespace": "default"}}))
    body = ("\n".join(lines_out) + "\n").encode()
    req = urllib.request.Request(f"{ES}/{INDEX}/_bulk?refresh=wait_for", body, method="POST",
                                 headers={"Authorization": "Basic " + AUTH,
                                          "Content-Type": "application/json"})
    r = json.load(urllib.request.urlopen(req, context=ctx))
    errs = [i for i in r["items"] if i["create"].get("status", 200) >= 300]
    fs = [i for i in r["items"] if i["create"].get("failure_store") == "used"]
    print(f"submitted {len(r['items'])}, errors {len(errs)}, failure store {len(fs)}")
    if errs: print(json.dumps(errs[0])[:400])
    if fs: print("FAILED INGEST:", json.dumps(fs[0])[:400])

main()
