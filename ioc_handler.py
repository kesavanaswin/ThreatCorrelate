"""
IOC Handler - Identifies type of Indicator of Compromise
Supports: IPv4, IPv6, Domains, and File Hashes (MD5, SHA1, SHA256)
"""

import re
import hashlib

class IOCHandler:
    """
    Identifies the type of IOC (Indicator of Compromise)
    """
    
    @staticmethod
    def is_ipv4(value):
        """Check if value is IPv4 address"""
        # Pattern: 192.168.1.1
        ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        return re.match(ipv4_pattern, value) is not None
    
    @staticmethod
    def is_ipv6(value):
        """Check if value is IPv6 address"""
        # Simple IPv6 check
        ipv6_pattern = r'^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4})$'
        return re.match(ipv6_pattern, value) is not None
    
    @staticmethod
    def is_domain(value):
        """Check if value is a domain name"""
        # Pattern: example.com, malicious.org, etc.
        domain_pattern = r'^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        return re.match(domain_pattern, value) is not None
    
    @staticmethod
    def is_md5(value):
        """Check if value is MD5 hash (32 hex characters)"""
        return len(value) == 32 and all(c in '0123456789abcdefABCDEF' for c in value)
    
    @staticmethod
    def is_sha1(value):
        """Check if value is SHA1 hash (40 hex characters)"""
        return len(value) == 40 and all(c in '0123456789abcdefABCDEF' for c in value)
    
    @staticmethod
    def is_sha256(value):
        """Check if value is SHA256 hash (64 hex characters)"""
        return len(value) == 64 and all(c in '0123456789abcdefABCDEF' for c in value)
    
    @staticmethod
    def is_hash(value):
        """Check if value is any type of hash"""
        return IOCHandler.is_md5(value) or IOCHandler.is_sha1(value) or IOCHandler.is_sha256(value)
    
    @staticmethod
    def detect_ioc_type(value):
        """
        Detect the type of IOC
        Returns: 'ip', 'domain', 'hash', or 'unknown'
        """
        value = value.strip()
        
        if IOCHandler.is_ipv4(value):
            return 'ipv4'
        elif IOCHandler.is_ipv6(value):
            return 'ipv6'
        elif IOCHandler.is_domain(value):
            return 'domain'
        elif IOCHandler.is_hash(value):
            return 'hash'
        else:
            return 'unknown'
    
    @staticmethod
    def validate_ioc(value):
        """
        Validate if IOC is recognized
        Returns: True if valid IOC, False otherwise
        """
        ioc_type = IOCHandler.detect_ioc_type(value)
        return ioc_type != 'unknown'
    
    @staticmethod
    def parse_ioc_batch(iocs):
        """
        Parse a batch of IOCs
        Input: List of IOC strings
        Returns: List of dictionaries with IOC and type
        """
        parsed = []
        for ioc in iocs:
            ioc_type = IOCHandler.detect_ioc_type(ioc)
            if ioc_type != 'unknown':
                parsed.append({
                    'ioc': ioc,
                    'type': ioc_type
                })
        return parsed


# Test the IOC Handler
if __name__ == "__main__":
    print("Testing IOC Handler...\n")
    
    test_cases = [
        "192.168.1.1",
        "8.8.8.8",
        "malicious.com",
        "phishing-site.org",
        "5d41402abc4b2a76b9719d911017c592",  # MD5
        "356a192b7913b04c54574d18c28d46e6395428ab",  # SHA1
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # SHA256
        "invalid-ioc"
    ]
    
    for test in test_cases:
        ioc_type = IOCHandler.detect_ioc_type(test)
        print(f"IOC: {test}")
        print(f"Type: {ioc_type}")
        print(f"Valid: {IOCHandler.validate_ioc(test)}\n")
