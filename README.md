# Threat-Intelligence-Automator-TIA-
A Python-based security analysis tool that extracts and analyzes PCAP network traffic, detects threats, and correlates logs with Virus total and AbuseIPB Threat Intelligence Feeds.

## Requirements
Python 3.6 or higher

Required Python libraries:   

`pip install pandas, requests, scapy, argparse, json, py_markdown_table, `

## Execution Instructions
1. Clone the Repository
Clone the repository to your local machine:   

`git clone https://github.com/c1ph3rbnuk/Threat-Intelligence-Automator-TIA-.git`   

`cd Threat-Intelligence-Automator-TIA\tia`

## Run the Tool
Execute the script with the following command:

`python packet-intel.py path/to/your/file.pcap`

### Arguments:
pcap_file: Path to the PCAP file to analyze.