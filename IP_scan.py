import csv
import requests
import time

# ================= CONFIG =================
VT_API_KEY = 'YOUR API KEY HERE'  # VirusTotal API key
INPUT_FILE = r'PATH TO INPUT FILE'  #Path to input file
OUTPUT_FILE = r'PATH TO OUTPUT FILE'    #Path to output file
RATE_SLEEP = 15  # seconds between VT requests (~4 per minute free tier)

# ================= CSV FIELDS =================
FIELDNAMES = [
    "IP Address",
    "Domains",
    "Country",
    "Region",
    "City",
    "Lat",
    "Lon",
    "AS Owner",
    "ISP",
    "Malicious",
    "Suspicious",
    "Undetected",
    "Harmless",
    "Total Reports",
    "Is Known Malicious"
]

# ================= FUNCTIONS =================
def get_domains(ip_address):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}/domains"
    headers = {'x-apikey': VT_API_KEY}
    domains_list = []
    try:
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code == 200:
            data = resp.json().get("data", [])
            for d in data:
                name = d.get("id")
                if name:
                    domains_list.append(name)
    except Exception:
        pass
    return domains_list if domains_list else ["None"]

def check_ip(ip_address):
    result = {
        "IP Address": ip_address,
        "Domains": "None",
        "Country": None,
        "AS Owner": None,
        "Malicious": 0,
        "Suspicious": 0,
        "Undetected": 0,
        "Harmless": 0,
        "Total Reports": 0,
        "Is Known Malicious": "NO"
    }

    if not ip_address:
        return result

    url = f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}'
    headers = {'x-apikey': VT_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=30)
        if resp.status_code != 200:
            return result
        js = resp.json()
    except Exception:
        return result

    attrs = js.get("data", {}).get("attributes", {})
    result["Country"] = attrs.get("country")
    result["AS Owner"] = attrs.get("as_owner")
    result["Domains"] = ", ".join(get_domains(ip_address))

    stats = attrs.get("last_analysis_stats", {})
    result["Malicious"] = stats.get("malicious", 0)
    result["Suspicious"] = stats.get("suspicious", 0)
    result["Undetected"] = stats.get("undetected", 0)
    result["Harmless"] = stats.get("harmless", 0)
    result["Total Reports"] = sum([
        result["Malicious"],
        result["Suspicious"],
        result["Undetected"],
        result["Harmless"]
    ])
    result["Is Known Malicious"] = "YES" if result["Malicious"] > 0 else "NO"

    return result

def geolocate_ip(ip_address):
    """Free geolocation using ip-api.com"""
    url = f"http://ip-api.com/json/{ip_address}"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            js = resp.json()
            if js.get("status") == "success":
                return {
                    "Country": js.get("country"),
                    "Region": js.get("regionName"),
                    "City": js.get("city"),
                    "Lat": js.get("lat"),
                    "Lon": js.get("lon"),
                    "ISP": js.get("isp")
                }
    except Exception:
        pass
    return {"Country": None, "Region": None, "City": None, "Lat": None, "Lon": None, "ISP": None}

# ================= MAIN SCRIPT =================
try:
    with open(INPUT_FILE, 'r', encoding='utf-8-sig') as infile:
        reader = csv.DictReader(infile)
        ip_list = list(reader)

    with open(OUTPUT_FILE, 'w', newline='', encoding='utf-8') as outfile:
        writer = csv.DictWriter(outfile, fieldnames=FIELDNAMES)
        writer.writeheader()

        for row in ip_list:
            ip_address = row.get("IP Address") or row.get("IP") or row.get("ip") or row.get("ip_address")
            if not ip_address:
                print("Skipping row, no IP found:", row)
                continue

            print("Scanning IP:", ip_address)

            vt_data = check_ip(ip_address)
            geo_data = geolocate_ip(ip_address)

            # Merge VT + Geolocation
            data = {**vt_data, **geo_data}

            # Ensure Country is filled from Geo API if missing in VT
            if not data["Country"]:
                data["Country"] = geo_data.get("Country")

            writer.writerow(data)
            outfile.flush()

            # Sleep to respect VT rate limits
            time.sleep(RATE_SLEEP)

    print("IP scan completed!")

except FileNotFoundError:
    print("Input file not found:", INPUT_FILE)
except Exception as e:
    print(f"Unexpected error: {e}")
