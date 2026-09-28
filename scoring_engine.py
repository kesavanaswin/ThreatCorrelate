"""
Scoring Engine - Weighted Confidence Scoring Formula
Combines results from multiple threat intelligence sources
"""

class ScoringEngine:
    """
    Weighted confidence scoring formula
    
    Weight Distribution:
    - VirusTotal: 50% (0.5) - Aggregates many AV engines, highest reliability
    - AbuseIPDB: 30% (0.3) - Community-based IP reputation
    - AlienVault OTX: 20% (0.2) - Open threat exchange data
    
    Score Range: 0-100
    Verdict: Malicious (80-100), Suspicious (50-79), Low Risk (20-49), Clean (0-19)
    """
    
    # Weight configuration
    WEIGHTS = {
        'virustotal': 0.5,
        'abuseipdb': 0.3,
        'otx': 0.2
    }
    
    # Thresholds for verdicts
    THRESHOLDS = {
        'malicious': 80,
        'suspicious': 50,
        'low_risk': 20,
        'clean': 0
    }
    
    @staticmethod
    def normalize_score(value, source_type):
        """
        Normalize scores from different sources to 0-100 scale
        
        VirusTotal: Returns count of detections (0-N engines)
        AbuseIPDB: Returns score 0-100
        OTX: Returns count of pulses (0-N)
        """
        if source_type == 'virustotal':
            # VirusTotal returns detection count
            # Normalize: if 5+ detections = high risk
            # Cap at 100
            return min((value / 5) * 100, 100)
        
        elif source_type == 'abuseipdb':
            # AbuseIPDB already returns 0-100
            return value
        
        elif source_type == 'otx':
            # OTX returns pulse count
            # Normalize: if 3+ pulses = high risk
            return min((value / 3) * 100, 100)
        
        else:
            return 0
    
    @staticmethod
    def calculate_weighted_score(vt_score, abuseipdb_score, otx_score):
        """
        Calculate final confidence score using weighted formula
        
        Formula:
        Final_Score = (VT × 0.5) + (AbuseIPDB × 0.3) + (OTX × 0.2)
        
        Args:
            vt_score: VirusTotal score (0-100)
            abuseipdb_score: AbuseIPDB score (0-100)
            otx_score: OTX score (0-100)
        
        Returns:
            Final confidence score (0-100)
        """
        # Ensure all scores are 0-100
        vt_score = max(0, min(100, vt_score))
        abuseipdb_score = max(0, min(100, abuseipdb_score))
        otx_score = max(0, min(100, otx_score))
        
        # Apply weighted formula
        final_score = (
            (vt_score * ScoringEngine.WEIGHTS['virustotal']) +
            (abuseipdb_score * ScoringEngine.WEIGHTS['abuseipdb']) +
            (otx_score * ScoringEngine.WEIGHTS['otx'])
        )
        
        return round(final_score, 2)
    
    @staticmethod
    def get_verdict(score):
        """
        Get verdict based on confidence score
        
        Malicious: 80-100 (High confidence threat)
        Suspicious: 50-79 (Requires investigation)
        Low Risk: 20-49 (Minor concerns)
        Clean: 0-19 (Appears safe)
        """
        score = float(score)
        
        if score >= ScoringEngine.THRESHOLDS['malicious']:
            return 'Malicious'
        elif score >= ScoringEngine.THRESHOLDS['suspicious']:
            return 'Suspicious'
        elif score >= ScoringEngine.THRESHOLDS['low_risk']:
            return 'Low Risk'
        else:
            return 'Clean'
    
    @staticmethod
    def get_risk_color(verdict):
        """
        Get color code for risk level (for dashboard display)
        """
        colors = {
            'Malicious': '#FF0000',      # Red
            'Suspicious': '#FFA500',     # Orange
            'Low Risk': '#FFFF00',       # Yellow
            'Clean': '#00FF00'           # Green
        }
        return colors.get(verdict, '#808080')  # Gray for unknown
    
    @staticmethod
    def score_ioc(vt_data, abuseipdb_data, otx_data, ioc_type):
        """
        Score a single IOC using data from all three sources
        
        Args:
            vt_data: VirusTotal response
            abuseipdb_data: AbuseIPDB response
            otx_data: OTX response
            ioc_type: Type of IOC ('ip', 'domain', 'hash')
        
        Returns:
            Dictionary with score, verdict, and details
        """
        
        # Extract detection counts from each source
        vt_detections = 0
        if vt_data and 'detections' in vt_data:
            vt_detections = vt_data['detections']
        
        abuseipdb_score = 0
        if abuseipdb_data and 'abuseConfidenceScore' in abuseipdb_data:
            abuseipdb_score = abuseipdb_data['abuseConfidenceScore']
        
        otx_pulses = 0
        if otx_data and 'pulses' in otx_data:
            otx_pulses = otx_data['pulses']
        
        # Normalize scores
        vt_normalized = ScoringEngine.normalize_score(vt_detections, 'virustotal')
        abuseipdb_normalized = ScoringEngine.normalize_score(abuseipdb_score, 'abuseipdb')
        otx_normalized = ScoringEngine.normalize_score(otx_pulses, 'otx')
        
        # Calculate final score
        final_score = ScoringEngine.calculate_weighted_score(
            vt_normalized,
            abuseipdb_normalized,
            otx_normalized
        )
        
        # Get verdict
        verdict = ScoringEngine.get_verdict(final_score)
        
        return {
            'score': final_score,
            'verdict': verdict,
            'color': ScoringEngine.get_risk_color(verdict),
            'vt_score': vt_normalized,
            'abuseipdb_score': abuseipdb_normalized,
            'otx_score': otx_normalized,
            'vt_detections': vt_detections,
            'abuseipdb_confidence': abuseipdb_score,
            'otx_pulses': otx_pulses
        }


# Test the Scoring Engine
if __name__ == "__main__":
    print("Testing Scoring Engine...\n")
    
    # Test Case 1: High risk (likely malicious)
    print("Test Case 1: High Risk IOC")
    print("="*50)
    vt_data = {'detections': 8}
    abuseipdb_data = {'abuseConfidenceScore': 95}
    otx_data = {'pulses': 5}
    
    result = ScoringEngine.score_ioc(vt_data, abuseipdb_data, otx_data, 'ip')
    print(f"Score: {result['score']}")
    print(f"Verdict: {result['verdict']}")
    print(f"Color: {result['color']}\n")
    
    # Test Case 2: Low risk (likely clean)
    print("Test Case 2: Low Risk IOC")
    print("="*50)
    vt_data = {'detections': 0}
    abuseipdb_data = {'abuseConfidenceScore': 5}
    otx_data = {'pulses': 0}
    
    result = ScoringEngine.score_ioc(vt_data, abuseipdb_data, otx_data, 'ip')
    print(f"Score: {result['score']}")
    print(f"Verdict: {result['verdict']}")
    print(f"Color: {result['color']}\n")
    
    # Test Case 3: Medium risk (suspicious)
    print("Test Case 3: Medium Risk IOC")
    print("="*50)
    vt_data = {'detections': 2}
    abuseipdb_data = {'abuseConfidenceScore': 50}
    otx_data = {'pulses': 1}
    
    result = ScoringEngine.score_ioc(vt_data, abuseipdb_data, otx_data, 'ip')
    print(f"Score: {result['score']}")
    print(f"Verdict: {result['verdict']}")
    print(f"Color: {result['color']}")
