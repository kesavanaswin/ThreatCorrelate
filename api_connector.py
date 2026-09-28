"""
API Connector - Queries threat intelligence APIs
Supports: VirusTotal, AbuseIPDB, AlienVault OTX
"""

import os
import requests
from dotenv import load_dotenv
import time

# Load environment variables
load_dotenv()

class APIConnector:
    """
    Connects to multiple threat intelligence APIs
    """
    
    def __init__(self):
        """Initialize API keys from .env file"""
        self.vt_api_key = os.getenv('VIRUSTOTAL_API_KEY')
        self.abuseipdb_api_key = os.getenv('ABUSEIPDB_API_KEY')
        self.otx_api_key = os.getenv('OTX_API_KEY')
        
        # API URLs
        self.VT_URL = "https://www.virustotal.com/api/v3"
        self.ABUSEIPDB_URL = "https://api.abuseipdb.com/api/v2"
        self.OTX_URL = "https://otx.alienvault.com/api/v1"
        
        # Rate limiting
        self.request_count = 0
        self.rate_limit_delay = 0.5  # seconds between requests
    
    def _rate_limit(self):
        """Implement rate limiting between API calls"""
        time.sleep(self.rate_limit_delay)
    
    def query_virustotal(self, ioc, ioc_type):
        """
        Query VirusTotal API
        
        Args:
            ioc: Indicator of compromise
            ioc_type: Type of IOC ('ipv4', 'domain', 'hash')
        
        Returns:
            Dictionary with VirusTotal data
        """
        try:
            self._rate_limit()
            
            headers = {
                "x-apikey": self.vt_api_key
            }
            
            # Map IOC type to VirusTotal endpoint
            if ioc_type in ['ipv4', 'ipv6']:
                endpoint = f"{self.VT_URL}/ip_addresses/{ioc}"
            elif ioc_type == 'domain':
                endpoint = f"{self.VT_URL}/domains/{ioc}"
            elif ioc_type == 'hash':
                endpoint = f"{self.VT_URL}/files/{ioc}"
            else:
                return {'error': 'Invalid IOC type'}
            
            response = requests.get(endpoint, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Extract relevant information
                if 'data' in data:
                    attributes = data['data'].get('attributes', {})
                    
                    # Count malicious detections
                    last_analysis = attributes.get('last_analysis_stats', {})
                    malicious_count = last_analysis.get('malicious', 0)
                    undetected_count = last_analysis.get('undetected', 0)
                    suspicious_count = last_analysis.get('suspicious', 0)
                    
                    # Get tags
                    tags = attributes.get('tags', [])
                    
                    return {
                        'status': 'success',
                        'detections': malicious_count,
                        'suspicious': suspicious_count,
                        'undetected': undetected_count,
                        'tags': tags,
                        'last_analysis_date': attributes.get('last_analysis_date'),
                        'categories': attributes.get('categories', {}),
                        'reputation': attributes.get('reputation', 0)
                    }
                
                return {'status': 'success', 'detections': 0, 'tags': []}
            
            elif response.status_code == 404:
                return {'status': 'not_found', 'detections': 0, 'tags': []}
            
            else:
                return {'status': 'error', 'message': f'API Error {response.status_code}'}
        
        except requests.exceptions.Timeout:
            return {'status': 'timeout', 'error': 'Request timed out'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def query_abuseipdb(self, ioc, ioc_type):
        """
        Query AbuseIPDB API (for IP addresses only)
        
        Args:
            ioc: IP address
            ioc_type: Type of IOC
        
        Returns:
            Dictionary with AbuseIPDB data
        """
        try:
            if ioc_type not in ['ipv4', 'ipv6']:
                return {'status': 'not_applicable', 'abuseConfidenceScore': 0, 'tags': []}
            
            self._rate_limit()
            
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ioc,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(
                f"{self.ABUSEIPDB_URL}/check",
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if 'data' in data:
                    abusedata = data['data']
                    
                    return {
                        'status': 'success',
                        'abuseConfidenceScore': abusedata.get('abuseConfidenceScore', 0),
                        'usageType': abusedata.get('usageType', 'Unknown'),
                        'isp': abusedata.get('isp', 'Unknown'),
                        'domain': abusedata.get('domain', 'Unknown'),
                        'totalReports': abusedata.get('totalReports', 0),
                        'tags': abusedata.get('usageType', [])
                    }
                
                return {'status': 'not_found', 'abuseConfidenceScore': 0}
            
            else:
                return {'status': 'error', 'message': f'API Error {response.status_code}'}
        
        except requests.exceptions.Timeout:
            return {'status': 'timeout', 'error': 'Request timed out'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def query_otx(self, ioc, ioc_type):
        """
        Query AlienVault OTX API
        
        Args:
            ioc: Indicator of compromise
            ioc_type: Type of IOC
        
        Returns:
            Dictionary with OTX data
        """
        try:
            self._rate_limit()
            
            headers = {
                'X-OTX-API-KEY': self.otx_api_key,
                'Accept': 'application/json'
            }
            
            # Map IOC type to OTX endpoint
            if ioc_type in ['ipv4', 'ipv6']:
                endpoint = f"{self.OTX_URL}/indicators/IPv4/{ioc}/general"
            elif ioc_type == 'domain':
                endpoint = f"{self.OTX_URL}/indicators/domain/{ioc}/general"
            elif ioc_type == 'hash':
                endpoint = f"{self.OTX_URL}/indicators/file/{ioc}/general"
            else:
                return {'status': 'error', 'error': 'Invalid IOC type'}
            
            response = requests.get(endpoint, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                pulse_count = data.get('pulse_info', {}).get('count', 0)
                tags = []
                
                # Extract tags from pulses
                pulses = data.get('pulse_info', {}).get('pulses', [])
                for pulse in pulses:
                    tags.extend(pulse.get('tags', []))
                
                return {
                    'status': 'success',
                    'pulses': pulse_count,
                    'tags': list(set(tags)),  # Remove duplicates
                    'reputation': data.get('reputation', 0),
                    'alexa_rank': data.get('alexa_rank', 'N/A'),
                    'whois': data.get('whois', 'N/A')
                }
            
            elif response.status_code == 404:
                return {'status': 'not_found', 'pulses': 0, 'tags': []}
            
            else:
                return {'status': 'error', 'message': f'API Error {response.status_code}'}
        
        except requests.exceptions.Timeout:
            return {'status': 'timeout', 'error': 'Request timed out'}
        except Exception as e:
            return {'status': 'error', 'error': str(e)}
    
    def query_all_sources(self, ioc, ioc_type):
        """
        Query all three threat intelligence sources in parallel
        
        Args:
            ioc: Indicator of compromise
            ioc_type: Type of IOC
        
        Returns:
            Dictionary with results from all three sources
        """
        results = {
            'ioc': ioc,
            'ioc_type': ioc_type,
            'virustotal': self.query_virustotal(ioc, ioc_type),
            'abuseipdb': self.query_abuseipdb(ioc, ioc_type),
            'otx': self.query_otx(ioc, ioc_type)
        }
        
        return results
    
    def get_combined_tags(self, all_results):
        """
        Combine tags from all three sources
        
        Args:
            all_results: Results from all three APIs
        
        Returns:
            List of combined unique tags
        """
        tags = set()
        
        if 'virustotal' in all_results:
            tags.update(all_results['virustotal'].get('tags', []))
        
        if 'abuseipdb' in all_results:
            tags.update(all_results['abuseipdb'].get('tags', []))
        
        if 'otx' in all_results:
            tags.update(all_results['otx'].get('tags', []))
        
        return list(tags)


# Test the API Connector
if __name__ == "__main__":
    print("Testing API Connector...\n")
    
    # Check if API keys are loaded
    connector = APIConnector()
    
    if not connector.vt_api_key:
        print("✗ VirusTotal API key not found in .env")
    else:
        print("✓ VirusTotal API key loaded")
    
    if not connector.abuseipdb_api_key:
        print("✗ AbuseIPDB API key not found in .env")
    else:
        print("✓ AbuseIPDB API key loaded")
    
    if not connector.otx_api_key:
        print("✗ OTX API key not found in .env")
    else:
        print("✓ OTX API key loaded")
    
    print("\nAPI Connector ready to use!")
    print("\nExample usage:")
    print("  connector = APIConnector()")
    print("  results = connector.query_all_sources('8.8.8.8', 'ipv4')")
    print("  print(results)")
