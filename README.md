# Bulk-IP-and-Domain-Scanners
Scans a list of IP addresses or Domain names with your VirusTotal API key
This is a modification of ph1nx's VirusTotal-Bulk-IP-Scanner found at https://github.com/ph1nx/VirusTotal-Bulk-IP-Scanner?tab=readme-ov-file#virustotal-bulk-ip-scanner to include more fieldnames. 

Note: ChatGPT was used to assist in this process.

Requirements

Python 3.x
requests library
Install the required Python package using pip:

    pip install requests

Usage of IP scanner:

    In the script file, replace APIKEY with your own VirusTotal API key.
    Prepare a CSV file (IP_list.csv) with the first cell called 'IP Address' and the IP addresses in the collumn below it.
    Prepare a CSV file (IP_results.csv). This is where the output will be.
    In the script file, adjust file paths (input_file, output_file) as per your local directory structure.
    If you have a premium API key, you can adjust the cooldown which by default is the free tier or 4 scans per minute.
    Run the script.

Usage of Domain scanner:

    Same as above.
    Yes, the names of the input and output files along with the header of the input file are still called IP.
    Just add domains in the collumn of the input file in the same place you would put the IP addresses.
