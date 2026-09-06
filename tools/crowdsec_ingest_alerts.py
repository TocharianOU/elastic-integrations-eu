#!/usr/bin/env python3
"""Replay captured CrowdSec alerts into an Elasticsearch cluster through the
installed crowdsec.alert pipeline.

The scenarios, events and meta are the authentic ones captured from a live
CrowdSec. Two production-shape enrichments are added, because a CrowdSec running
offline (DISABLE_ONLINE_API) emits alerts with no geo/AS, and a capture run in
one burst has every alert inside the same second:

  - each distinct source is given a real public IP with country + coordinates +
    AS, exactly the shape CrowdSec attaches when its GeoIP is enabled;
  - start_at/stop_at are respread across the last 24h with a diurnal weighting.

Every alert is replayed a few times with jitter so the dashboard has volume.
"""
import json, os, random, urllib.request, ssl, base64, datetime, copy, sys

# Never hardcode these. Export before running:
#   export ES_URL=https://your-cluster:9200 ES_USER=... ES_PASS=...
ES = os.environ["ES_URL"]
AUTH = base64.b64encode(f"{os.environ['ES_USER']}:{os.environ['ES_PASS']}".encode()).decode()
INDEX = "logs-crowdsec.alert-default"
ctx = ssl.create_default_context(); ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE

# distinct public sources with real geo, standing in for what CrowdSec's own
# GeoIP would attach on an internet-facing install
SOURCES = [
  {"ip":"45.83.64.10","cn":"NL","lat":"52.3676","lon":"4.9041","as":"206264","asn":"Amarutu Technology"},
  {"ip":"185.220.101.34","cn":"DE","lat":"50.1109","lon":"8.6821","as":"205100","asn":"F3 Netze e.V."},
  {"ip":"92.118.39.80","cn":"FR","lat":"48.8566","lon":"2.3522","as":"49447","asn":"Semenchenko"},
  {"ip":"193.32.162.150","cn":"RU","lat":"55.7558","lon":"37.6173","as":"202425","asn":"IP Volume inc"},
  {"ip":"104.244.72.115","cn":"US","lat":"40.7128","lon":"-74.0060","as":"53667","asn":"FranTech"},
  {"ip":"212.70.149.150","cn":"GB","lat":"51.5074","lon":"-0.1278","as":"9009","asn":"M247"},
  {"ip":"159.223.44.20","cn":"SG","lat":"1.3521","lon":"103.8198","as":"14061","asn":"DigitalOcean"},
  {"ip":"1.15.62.44","cn":"CN","lat":"39.9042","lon":"116.4074","as":"45090","asn":"Tencent"},
]

def load_alerts():
    seen=set(); out=[]
    for l in open("/data/crowdsec/capture/notifications.log"):
        for a in json.loads(json.loads(l)["body"]):
            k=(a["scenario"], a["source"]["value"])
            if k in seen: continue
            seen.add(k); out.append(a)
    return out

def weighted_time():
    # diurnal weighting over last 24h
    hour = random.choices(range(24),
        weights=[3,2,2,1,1,1,2,4,6,8,9,9,8,8,9,10,9,8,7,6,6,5,4,3])[0]
    now = datetime.datetime.now(datetime.timezone.utc)
    base = now - datetime.timedelta(hours=random.randint(0,23))
    t = base.replace(hour=hour, minute=random.randint(0,59), second=random.randint(0,59),
                     microsecond=random.randint(0,999999))
    if t > now: t -= datetime.timedelta(days=1)
    return t

def enrich(a, src):
    a=copy.deepcopy(a)
    dur = random.uniform(0.5, 90)
    start = weighted_time()
    stop = start + datetime.timedelta(seconds=dur)
    a["start_at"]=start.strftime("%Y-%m-%dT%H:%M:%S.%f000Z")
    a["stop_at"]=stop.strftime("%Y-%m-%dT%H:%M:%S.%f000Z")
    s=a["source"]
    s["ip"]=src["ip"]; s["value"]=src["ip"]; s["scope"]="Ip"
    s["cn"]=src["cn"]; s["latitude"]=src["lat"]; s["longitude"]=src["lon"]
    s["as_number"]=src["as"]; s["as_name"]=src["asn"]
    for d in a.get("decisions",[]):
        d["value"]=src["ip"]
    return a

def bulk(docs):
    lines=[]
    for d in docs:
        lines.append(json.dumps({"create":{}}))
        # feed as the logfile input would: the raw alert JSON as message
        # data_stream.* are constant_keyword with no value in the mapping; only
        # Elastic Agent sets them. Hand-ingested docs must carry them or every
        # dashboard/search filter on data_stream.dataset matches nothing.
        lines.append(json.dumps({"message": json.dumps(d),
                                 "tags": ["crowdsec-alert","forwarded"],
                                 "data_stream": {"type":"logs","dataset":"crowdsec.alert","namespace":"default"}}))
    body=("\n".join(lines)+"\n").encode()
    # No ?pipeline= : the data stream template already sets default_pipeline to
    # the installed version. Pinning a version here silently breaks on every
    # package upgrade - and ES 9 diverts the failures into the failure store
    # while still reporting errors:false, so the bulk looks successful.
    url=f"{ES}/{INDEX}/_bulk?refresh=wait_for"
    req=urllib.request.Request(url, body, method="POST",
        headers={"Authorization":"Basic "+AUTH,"Content-Type":"application/json"})
    r=json.load(urllib.request.urlopen(req, context=ctx))
    errs=[i for i in r["items"] if i["create"].get("status",200)>=300]
    # A doc rejected by the pipeline still returns 201; the only tell is that
    # it landed in the failure store instead of the data stream.
    fs=[i for i in r["items"] if i["create"].get("failure_store")=="used"]
    return len(r["items"]), errs, fs

def main():
    alerts=load_alerts()
    target = int(sys.argv[1]) if len(sys.argv)>1 else 110
    docs=[]
    while len(docs)<target:
        a=random.choice(alerts)
        src=random.choice(SOURCES)
        docs.append(enrich(a, src))
    n,errs,fs=bulk(docs)
    print(f"submitted {n}, errors {len(errs)}, diverted to failure store {len(fs)}")
    if errs: print(json.dumps(errs[0], indent=1)[:800])
    if fs:
        print("FAILED INGEST - docs went to the failure store, not the data stream")
        print(json.dumps(fs[0], indent=1)[:600])

main()
