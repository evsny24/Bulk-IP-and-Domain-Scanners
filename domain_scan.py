import csv
import json
import requests
import time
import os
import sys

# ================= CONFIG =================
VT_API_KEY = "API KEY HERE"  # <-- put your VirusTotal API key here
INPUT_FILE = r"Path to Input File"  #Path to input file
OUTPUT_FILE = r"Path to Output File"    #Path to output file
RATE_SLEEP = 15  # seconds between VT requests (~4 requests/min free tier)

# ================= CSV FIELDS =================
FIELDNAMES = [
    "Domain",
    "Resolved IP",
    "AS Owner",
    "Country",
    "Region",
    "City",
    "Lat",
    "Lon",
    "ISP",
    "Reputation",
    "Malicious",
    "Suspicious",
    "Undetected",
    "Harmless",
    "Total Reports",
    "Is Known Malicious",
    "Categories",
    "Tags",
    "Registrar",
    "Creation Date",
    "Expiration Date",
    "DNS A",
    "DNS MX",
    "DNS NS",
    "DNS TXT",
    "DNS SOA",
    "HTTPS Common Name",
    "HTTPS Issuer",
    "HTTPS Valid From",
    "HTTPS Valid To",
    "WHOIS",
    "Error"
]

# ================= HELPERS =================
def safe_request(url, headers=None, timeout=20):
    """Perform a GET request and return (status_code, json_or_text)."""
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        try:
            return r.status_code, r.json()
        except Exception:
            return r.status_code, r.text
    except Exception as e:
        return None, str(e)

def vt_domain_report(domain):
    """Fetch domain-level info from VirusTotal. Returns dict of VT fields and 'Error' on failure."""
    base = {
        "Domain": domain,
        "Resolved IP": None,
        "AS Owner": None,
        "Reputation": None,
        "Malicious": 0,
        "Suspicious": 0,
        "Undetected": 0,
        "Harmless": 0,
        "Total Reports": 0,
        "Is Known Malicious": "NO",
        "Categories": "",
        "Tags": "",
        "Registrar": "",
        "Creation Date": "",
        "Expiration Date": "",
        "DNS A": "",
        "DNS MX": "",
        "DNS NS": "",
        "DNS TXT": "",
        "DNS SOA": "",
        "HTTPS Common Name": "",
        "HTTPS Issuer": "",
        "HTTPS Valid From": "",
        "HTTPS Valid To": "",
        "WHOIS": "",
        "Error": ""
    }

    if not domain:
        base["Error"] = "No domain provided"
        return base

    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    headers = {"x-apikey": VT_API_KEY}

    status, data = safe_request(url, headers=headers, timeout=25)

    if status != 200:
        base["Error"] = f"VT API status: {status} - {str(data)[:200]}"
        return base

    try:
        attributes = data.get("data", {}).get("attributes", {})

        # reputation & stats
        base["Reputation"] = attributes.get("reputation")
        stats = attributes.get("last_analysis_stats", {}) or {}
        base["Malicious"] = stats.get("malicious", 0)
        base["Suspicious"] = stats.get("suspicious", 0)
        base["Undetected"] = stats.get("undetected", 0)
        base["Harmless"] = stats.get("harmless", 0)
        # total reports - safe sum
        try:
            base["Total Reports"] = int(base["Malicious"]) + int(base["Suspicious"]) + int(base["Undetected"]) + int(base["Harmless"])
        except Exception:
            base["Total Reports"] = sum(int(x) if str(x).isdigit() else 0 for x in (base["Malicious"], base["Suspicious"], base["Undetected"], base["Harmless"]))
        base["Is Known Malicious"] = "YES" if int(base["Malicious"]) > 0 else "NO"

        # categories & tags
        categories = attributes.get("categories", {}) or {}
        if isinstance(categories, dict):
            # categories may be a mapping of source->category
            base["Categories"] = ", ".join(str(v) for v in categories.values())
        else:
            base["Categories"] = str(categories)

        tags = attributes.get("tags", []) or []
        if isinstance(tags, list):
            base["Tags"] = ", ".join(tags)
        else:
            base["Tags"] = str(tags)

        # whois, registrar, dates
        base["WHOIS"] = attributes.get("whois") or ""
        base["Registrar"] = attributes.get("registrar") or ""
        base["Creation Date"] = attributes.get("creation_date") or ""
        base["Expiration Date"] = attributes.get("expiration_date") or ""

        # last DNS records - extract A / MX / NS / TXT / SOA
        dns_records = attributes.get("last_dns_records", []) or []
        dns_a = []
        dns_mx = []
        dns_ns = []
        dns_txt = []
        dns_soa = []
        resolved_ip = None

        for rec in dns_records:
            rtype = rec.get("type", "")
            value = rec.get("value") or rec.get("data") or ""
            if rtype == "A":
                dns_a.append(value)
                if not resolved_ip:
                    resolved_ip = value
            elif rtype == "MX":
                dns_mx.append(value)
            elif rtype == "NS":
                dns_ns.append(value)
            elif rtype == "TXT":
                dns_txt.append(value)
            elif rtype == "SOA":
                dns_soa.append(value)

        base["DNS A"] = "; ".join(dns_a)
        base["DNS MX"] = "; ".join(dns_mx)
        base["DNS NS"] = "; ".join(dns_ns)
        base["DNS TXT"] = "; ".join(dns_txt)
        base["DNS SOA"] = "; ".join(dns_soa)
        base["Resolved IP"] = resolved_ip

        # HTTPS certificate
        https_cert = attributes.get("last_https_certificate") or {}
        subj = https_cert.get("subject", {}) or {}
        issuer = https_cert.get("issuer", {}) or {}
        validity = https_cert.get("validity", {}) or {}
        base["HTTPS Common Name"] = subj.get("CN", "") or ""
        base["HTTPS Issuer"] = issuer.get("CN", "") or ""
        base["HTTPS Valid From"] = validity.get("not_before") or ""
        base["HTTPS Valid To"] = validity.get("not_after") or ""

        # AS Owner: VirusTotal sometimes includes attribution in whois or categories; not always present for domains.
        # We'll leave AS Owner empty here; geolocation step will populate ISP/AS if possible.
        base["AS Owner"] = ""

    except Exception as e:
        base["Error"] = f"Parsing VT response error: {e}"

    return base

def geolocate_ip_free(ip):
    """Use ip-api.com to geolocate an IP. Returns dict with Country, Region, City, Lat, Lon, ISP, AS Owner."""
    default = {"Country": None, "Region": None, "City": None, "Lat": None, "Lon": None, "ISP": None, "AS Owner": None}
    if not ip:
        return default
    url = f"http://ip-api.com/json/{ip}"
    status, data = safe_request(url, timeout=10)
    if status == 200 and isinstance(data, dict) and data.get("status") == "success":
        return {
            "Country": data.get("country"),
            "Region": data.get("regionName"),
            "City": data.get("city"),
            "Lat": data.get("lat"),
            "Lon": data.get("lon"),
            "ISP": data.get("isp"),
            "AS Owner": data.get("as")
        }
    return default

# ================= MAIN PROCESS =================
def main():
    # quick checks
    if VT_API_KEY in (None, "", "YOUR_VT_API_KEY"):
        print("[ERROR] Set your VirusTotal API key in VT_API_KEY and re-run.")
        sys.exit(1)

    if not os.path.exists(os.path.dirname(OUTPUT_FILE)) and os.path.dirname(OUTPUT_FILE):
        try:
            os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)
        except Exception as e:
            print(f"[ERROR] Cannot create output directory: {e}")
            sys.exit(1)

    # Read input CSV
    try:
        with open(INPUT_FILE, "r", encoding="utf-8-sig") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
            input_headers = reader.fieldnames
    except FileNotFoundError:
        print(f"[ERROR] Input file not found: {INPUT_FILE}")
        sys.exit(1)
    except Exception as e:
        print(f"[ERROR] Could not read input file: {e}")
        sys.exit(1)

    print(f"[INFO] Detected input headers: {input_headers}")
    if not rows:
        print("[WARN] No rows found in input CSV.")
        sys.exit(0)

    # open output file
    try:
        out_f = open(OUTPUT_FILE, "w", newline="", encoding="utf-8")
    except Exception as e:
        print(f"[ERROR] Unable to open output file for writing: {e}")
        sys.exit(1)

    writer = csv.DictWriter(out_f, fieldnames=FIELDNAMES)
    writer.writeheader()
    out_f.flush()
    try:
        os.fsync(out_f.fileno())
    except Exception:
        pass

    # support many possible input header names; fallback to first column if none match
    candidate_headers = ["Domain", "domain", "URL", "url", "Host", "host", "hostname", "Hostname", "IP Address", "ip"]
    for idx, row in enumerate(rows, start=1):
        # try to pull domain from likely headers
        domain = None
        for h in candidate_headers:
            if h in row and row[h] and str(row[h]).strip():
                domain = str(row[h]).strip()
                break
        if not domain:
            # fallback: first non-empty cell
            for v in row.values():
                if v and str(v).strip():
                    domain = str(v).strip()
                    break

        if not domain:
            print(f"[ROW {idx}] No domain found in row; writing diagnostic and continuing.")
            error_row = {k: "" for k in FIELDNAMES}
            error_row["Domain"] = ""
            error_row["Error"] = "No domain found in input row"
            writer.writerow(error_row)
            out_f.flush()
            try:
                os.fsync(out_f.fileno())
            except Exception:
                pass
            continue

        print(f"[ROW {idx}] Scanning domain: {domain}")
        # default result dict
        try:
            vt = vt_domain_report(domain)
        except Exception as e:
            vt = {k: "" for k in FIELDNAMES}
            vt["Domain"] = domain
            vt["Error"] = f"Unhandled VT exception: {e}"

        # If VT returned a resolved IP, geolocate it
        resolved_ip = vt.get("Resolved IP")
        geo = geolocate_ip_free(resolved_ip) if resolved_ip else {"Country": None, "Region": None, "City": None, "Lat": None, "Lon": None, "ISP": None, "AS Owner": None}

        # Merge vt + geo into output row
        out_row = {
            "Domain": vt.get("Domain"),
            "Resolved IP": resolved_ip or "",
            "AS Owner": geo.get("AS Owner") or vt.get("AS Owner") or "",
            "Country": geo.get("Country") or "",
            "Region": geo.get("Region") or "",
            "City": geo.get("City") or "",
            "Lat": geo.get("Lat") or "",
            "Lon": geo.get("Lon") or "",
            "ISP": geo.get("ISP") or "",
            "Reputation": vt.get("Reputation") if vt.get("Reputation") is not None else "",
            "Malicious": vt.get("Malicious") or 0,
            "Suspicious": vt.get("Suspicious") or 0,
            "Undetected": vt.get("Undetected") or 0,
            "Harmless": vt.get("Harmless") or 0,
            "Total Reports": vt.get("Total Reports") or 0,
            "Is Known Malicious": vt.get("Is Known Malicious") or "NO",
            "Categories": vt.get("Categories") or "",
            "Tags": vt.get("Tags") or "",
            "Registrar": vt.get("Registrar") or "",
            "Creation Date": vt.get("Creation Date") or "",
            "Expiration Date": vt.get("Expiration Date") or "",
            "DNS A": vt.get("DNS A") or "",
            "DNS MX": vt.get("DNS MX") or "",
            "DNS NS": vt.get("DNS NS") or "",
            "DNS TXT": vt.get("DNS TXT") or "",
            "DNS SOA": vt.get("DNS SOA") or "",
            "HTTPS Common Name": vt.get("HTTPS Common Name") or "",
            "HTTPS Issuer": vt.get("HTTPS Issuer") or "",
            "HTTPS Valid From": vt.get("HTTPS Valid From") or "",
            "HTTPS Valid To": vt.get("HTTPS Valid To") or "",
            "WHOIS": vt.get("WHOIS") or "",
            "Error": vt.get("Error") or ""
        }

        # write and flush
        try:
            writer.writerow(out_row)
            out_f.flush()
            try:
                os.fsync(out_f.fileno())
            except Exception:
                pass
            print(f"[ROW {idx}] Written: domain={domain} malicious={out_row['Malicious']}")
        except Exception as e:
            print(f"[ROW {idx}] Failed to write row for {domain}: {e}")
            # attempt to write minimal error row
            err = {k: "" for k in FIELDNAMES}
            err["Domain"] = domain
            err["Error"] = f"CSV write error: {e}"
            try:
                writer.writerow(err)
                out_f.flush()
                try:
                    os.fsync(out_f.fileno())
                except Exception:
                    pass
            except Exception:
                print(f"[ROW {idx}] Also failed to write error row for {domain}")

        # rate limit sleep
        print(f"[ROW {idx}] Sleeping {RATE_SLEEP}s to respect VT rate limits...")
        time.sleep(RATE_SLEEP)

    out_f.close()
    print("[INFO] Domain scan finished. Output saved to:", OUTPUT_FILE)


if __name__ == "__main__":
    main()
