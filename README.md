# Bulk IP and Domain Scanners

A Python-based tool that scans a list of IP addresses or domain names using the VirusTotal API and outputs detailed results to a CSV file.

This project was inspired by ph1nx’s bulk IP scanner, but has been significantly redesigned and expanded. It includes additional data fields and supports both IP address and domain scanning within separate scripts.

> **Note:** Fields in the output CSV will remain blank if the requested data is not available from VirusTotal.

---

## Features

- Bulk scanning of IP addresses and domain names
- Integration with the VirusTotal API
- Expanded set of returned data fields compared to the original project
- CSV-based input and output for easy data handling
- Adjustable rate limiting for API usage tiers

---

## Requirements

- Python 3.x
- `requests` library

---

## Installation

Install dependencies with:

```bash
pip install requests
```
## Usage

### 1. Set Your VirusTotal API Key

Replace the placeholder in your script:

```python
API_KEY = "your_api_key_here"
```
### 2. Prepare Input File

Create a CSV file containing your IPs or domains.

Example (`input.csv`):

```csv
target
8.8.8.8
example.com
1.1.1.1
```
### 3. Run the Script

For IP scanning:

```bash
python ip_scanner.py
```
For domain scanning:
```
python domain_scanner.py
```
### 4. Output

Results will be saved to a CSV file (e.g., `output.csv`) with enriched data from VirusTotal.

---

## Notes on Rate Limiting

VirusTotal enforces strict API rate limits depending on your plan.

You can adjust delays in your script:

```python
time.sleep(15)  # Adjust based on your API tier
```
- Free tier: ~4 requests/minute  
- Premium tiers allow higher throughput  

---

## Disclaimer

This tool is intended for educational and security research purposes only. Ensure you comply with VirusTotal's terms of service when using their API.

---

## Credits

- Inspired by ph1nx’s original bulk IP scanner and edited by me with assistance from AI tools
- Built and expanded for enhanced functionality and flexibility  
