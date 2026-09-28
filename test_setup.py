import os
from dotenv import load_dotenv

# Load API keys from .env
load_dotenv()

# Test if keys are loaded
vt_key = os.getenv("VIRUSTOTAL_API_KEY")
abuseipdb_key = os.getenv("ABUSEIPDB_API_KEY")
otx_key = os.getenv("OTX_API_KEY")

print("=" * 50)
print("ThreatCorrelate Setup Test")
print("=" * 50)

if vt_key:
    print("✓ VirusTotal API Key loaded!")
else:
    print("✗ VirusTotal key missing")

if abuseipdb_key:
    print("✓ AbuseIPDB API Key loaded!")
else:
    print("✗ AbuseIPDB key missing")

if otx_key:
    print("✓ OTX API Key loaded!")
else:
    print("✗ OTX key missing")

if vt_key and abuseipdb_key and otx_key:
    print("\n" + "=" * 50)
    print("✓ ALL SETUP SUCCESSFUL!")
    print("=" * 50)
    print("Ready to start coding Day 3!")
else:
    print("\n✗ Some keys are missing. Check your .env file")

print("=" * 50)