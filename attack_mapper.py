"""
Attack Mapper - Maps threat indicators to MITRE ATT&CK techniques
MITRE ATT&CK Framework: https://attack.mitre.org/
"""

class AttackMapper:
    """
    Maps IOC tags and findings to MITRE ATT&CK techniques
    """
    
    # Tag to MITRE ATT&CK technique mapping
    TAG_TO_ATTACK = {
        # Phishing-related
        'phishing': ['T1566', 'T1192', 'T1566.002'],
        'spam': ['T1566', 'T1593.002'],
        'malware': ['T1566.001', 'T1204.002'],
        'trojan': ['T1566.001', 'T1055'],
        'ransomware': ['T1486', 'T1565.001'],
        'worm': ['T1091'],
        
        # C2 / Network communication
        'c2': ['T1071', 'T1071.001', 'T1571'],
        'botnet': ['T1071', 'T1090'],
        'command_and_control': ['T1071', 'T1008'],
        'proxy': ['T1090', 'T1090.003'],
        
        # Exploitation
        'exploit': ['T1203', 'T1190', 'T1133'],
        'vulnerability': ['T1203', 'T1190'],
        'shellcode': ['T1086'],
        
        # Data theft
        'data_exfiltration': ['T1041', 'T1020.1'],
        'stealer': ['T1041', 'T1213'],
        'infostealer': ['T1041', 'T1005'],
        'spy': ['T1005', 'T1123'],
        
        # Brute force
        'brute_force': ['T1110', 'T1110.001'],
        'credential_dumping': ['T1110.004', 'T1003'],
        'password_attack': ['T1110'],
        
        # Malware variants
        'banker': ['T1041', 'T1111'],
        'cryptominer': ['T1496', 'T1570'],
        'rootkit': ['T1014', 'T1547.006'],
        'spyware': ['T1005', 'T1113'],
        'adware': ['T1071.001'],
        
        # Lateral movement
        'lateral_movement': ['T1570', 'T1570'],
        'persistence': ['T1547'],
        'privilege_escalation': ['T1134', 'T1136'],
        
        # Other malicious activities
        'ddos': ['T1498', 'T1498.001'],
        'blackhole': ['T1498'],
        'scanner': ['T1592', 'T1592.004'],
        'sinkhole': ['T1071'],
        'abuse': ['T1566.002'],
        'fraud': ['T1589.003'],
        'dga': ['T1568', 'T1568.002'],
        
        # Suspicious behaviors
        'suspicious': ['T1566', 'T1204'],
        'abnormal': ['T1566', 'T1204'],
        'reputation': ['T1071'],
        'blocked': ['T1008'],
    }
    
    # Confidence scores for different tag types
    TAG_CONFIDENCE = {
        'phishing': 85,
        'ransomware': 95,
        'malware': 90,
        'trojan': 88,
        'botnet': 85,
        'c2': 90,
        'exploit': 88,
        'data_exfiltration': 92,
        'stealer': 90,
        'brute_force': 80,
        'ddos': 85,
        'dga': 80,
        'suspicious': 60,
    }
    
    @staticmethod
    def get_attack_techniques(tags):
        """
        Get MITRE ATT&CK techniques for given tags
        
        Args:
            tags: List of tag strings
        
        Returns:
            List of MITRE ATT&CK technique IDs
        """
        techniques = set()
        
        if not tags:
            return []
        
        # Convert tags to lowercase and look up mappings
        tags_lower = [tag.lower().replace(' ', '_').replace('-', '_') for tag in tags]
        
        for tag in tags_lower:
            if tag in AttackMapper.TAG_TO_ATTACK:
                techniques.update(AttackMapper.TAG_TO_ATTACK[tag])
        
        return sorted(list(techniques))
    
    @staticmethod
    def get_technique_details(technique_id):
        """
        Get details about a MITRE ATT&CK technique
        
        Args:
            technique_id: Technique ID (e.g., 'T1566')
        
        Returns:
            Dictionary with technique details
        """
        technique_info = {
            'T1566': {
                'name': 'Phishing',
                'description': 'Send phishing messages to gain initial access',
                'subtypes': ['Email', 'Spearphishing', 'Link', 'Attachment']
            },
            'T1486': {
                'name': 'Data Encrypted for Impact',
                'description': 'Encrypt data as part of an extortion attack',
                'subtypes': ['Ransomware']
            },
            'T1110': {
                'name': 'Brute Force',
                'description': 'Attempt to gain access by guessing credentials',
                'subtypes': ['Password Guessing', 'Credential Stuffing']
            },
            'T1071': {
                'name': 'Application Layer Protocol',
                'description': 'Use standard protocols for command and control',
                'subtypes': ['Web Protocols', 'Mail Protocols', 'DNS']
            },
            'T1203': {
                'name': 'Exploitation for Client Execution',
                'description': 'Exploit vulnerabilities to execute code',
                'subtypes': []
            },
            'T1041': {
                'name': 'Exfiltration Over C2 Channel',
                'description': 'Steal data using command and control channel',
                'subtypes': []
            },
            'T1498': {
                'name': 'Network Denial of Service',
                'description': 'Launch DDoS attacks',
                'subtypes': ['Flood', 'Amplification']
            },
            'T1568': {
                'name': 'Dynamic Resolution',
                'description': 'Use dynamic DNS to evade detection',
                'subtypes': ['DGA', 'DNS']
            },
            'T1047': {
                'name': 'Windows Management Instrumentation',
                'description': 'Use WMI for lateral movement',
                'subtypes': []
            },
            'T1547': {
                'name': 'Boot or Logon Autostart Execution',
                'description': 'Achieve persistence through autostart mechanisms',
                'subtypes': []
            }
        }
        
        return technique_info.get(technique_id, {
            'name': f'Technique {technique_id}',
            'description': 'See MITRE ATT&CK framework for details',
            'subtypes': []
        })
    
    @staticmethod
    def map_to_tactics(techniques):
        """
        Map techniques to MITRE ATT&CK tactics
        
        Args:
            techniques: List of technique IDs
        
        Returns:
            Dictionary of tactics and their techniques
        """
        technique_to_tactics = {
            'T1566': ['Initial Access', 'Execution'],
            'T1486': ['Impact'],
            'T1110': ['Credential Access'],
            'T1071': ['Command and Control'],
            'T1203': ['Execution'],
            'T1041': ['Exfiltration'],
            'T1498': ['Impact'],
            'T1568': ['Command and Control'],
            'T1047': ['Execution'],
            'T1547': ['Persistence', 'Privilege Escalation']
        }
        
        tactics = {}
        for technique in techniques:
            if technique in technique_to_tactics:
                for tactic in technique_to_tactics[technique]:
                    if tactic not in tactics:
                        tactics[tactic] = []
                    tactics[tactic].append(technique)
        
        return tactics
    
    @staticmethod
    def generate_attack_summary(tags, score, verdict):
        """
        Generate a summary of attack techniques
        
        Args:
            tags: List of threat tags
            score: Threat score (0-100)
            verdict: Risk verdict
        
        Returns:
            Dictionary with attack summary
        """
        techniques = AttackMapper.get_attack_techniques(tags)
        tactics = AttackMapper.map_to_tactics(techniques)
        
        # Get primary technique
        primary_technique = techniques[0] if techniques else 'Unknown'
        primary_details = AttackMapper.get_technique_details(primary_technique)
        
        return {
            'primary_technique': primary_technique,
            'technique_name': primary_details.get('name', 'Unknown'),
            'all_techniques': techniques,
            'tactics': tactics,
            'technique_description': primary_details.get('description', ''),
            'confidence': score,
            'verdict': verdict
        }


# Test the Attack Mapper
if __name__ == "__main__":
    print("Testing Attack Mapper...\n")
    
    # Test Case 1: Phishing tags
    print("Test Case 1: Phishing Tags")
    print("="*50)
    tags = ['phishing', 'malware', 'spam']
    techniques = AttackMapper.get_attack_techniques(tags)
    print(f"Tags: {tags}")
    print(f"MITRE ATT&CK Techniques: {techniques}\n")
    
    # Test Case 2: Attack summary
    print("Test Case 2: Attack Summary")
    print("="*50)
    summary = AttackMapper.generate_attack_summary(
        ['ransomware', 'data_exfiltration'],
        score=92,
        verdict='Malicious'
    )
    print(f"Primary Technique: {summary['primary_technique']}")
    print(f"Technique Name: {summary['technique_name']}")
    print(f"Description: {summary['technique_description']}")
    print(f"Tactics: {list(summary['tactics'].keys())}")
    print(f"All Techniques: {summary['all_techniques']}")
