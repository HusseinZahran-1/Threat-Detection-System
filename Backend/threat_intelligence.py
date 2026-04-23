import requests
import hashlib
import json
import time
from datetime import datetime, timedelta
import redis
import os
class ThreatIntelligence:
    def __init__(self):
        self.cache = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
        self.api_keys = {
            'virustotal': os.getenv('VIRUSTOTAL_API_KEY', ''),
            'abuseipdb': os.getenv('ABUSEIPDB_API_KEY', ''),
            'alienvault': os.getenv('ALIENVAULT_API_KEY', '')
        }
        self.cache_ttl = 3600  # 1 hour
    
    def check_ip_reputation(self, ip_address):
        """Comprehensive IP reputation check"""
        cache_key = f"ip_reputation:{ip_address}"
        cached_result = self.cache.get(cache_key)
        
        if cached_result:
            return json.loads(cached_result)
        
        try:
            # Multiple threat intelligence sources
            vt_result = self.query_virustotal(ip_address)
            abuse_result = self.query_abuseipdb(ip_address)
            otx_result = self.query_alienvault(ip_address)
            
            # Calculate overall reputation score
            reputation_score = self.calculate_reputation_score(
                vt_result, abuse_result, otx_result
            )
            
            result = {
                'ip_address': ip_address,
                'reputation_score': reputation_score,
                'is_malicious': reputation_score > 70,
                'risk_level': self.get_risk_level(reputation_score),
                'sources': {
                    'virustotal': vt_result,
                    'abuseipdb': abuse_result,
                    'alienvault': otx_result
                },
                'last_updated': datetime.now().isoformat(),
                'tags': self.extract_threat_tags(vt_result, abuse_result, otx_result)
            }
            
            # Cache the result
            self.cache.setex(cache_key, self.cache_ttl, json.dumps(result))
            
            return result
            
        except Exception as e:
            print(f"❌ Threat intelligence error for {ip_address}: {e}")
            return self.get_fallback_result(ip_address)
    
    def query_virustotal(self, ip_address):
        """Query VirusTotal for IP reputation"""
        if not self.api_keys['virustotal']:
            return {'error': 'API key not configured'}
        
        try:
            headers = {'x-apikey': self.api_keys['virustotal']}
            response = requests.get(
                f'https://www.virustotal.com/api/v3/ip_addresses/{ip_address}',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get('data', {}).get('attributes', {})
                
                return {
                    'malicious': attributes.get('last_analysis_stats', {}).get('malicious', 0),
                    'suspicious': attributes.get('last_analysis_stats', {}).get('suspicious', 0),
                    'total_engines': sum(attributes.get('last_analysis_stats', {}).values()),
                    'reputation': attributes.get('reputation', 0),
                    'as_owner': attributes.get('as_owner', 'Unknown'),
                    'country': attributes.get('country', 'Unknown')
                }
            else:
                return {'error': f"API returned {response.status_code}"}
                
        except requests.RequestException as e:
            return {'error': f"Request failed: {str(e)}"}
    
    def query_abuseipdb(self, ip_address):
        """Query AbuseIPDB for IP reputation"""
        if not self.api_keys['abuseipdb']:
            return {'error': 'API key not configured'}
        
        try:
            headers = {'Key': self.api_keys['abuseipdb'], 'Accept': 'application/json'}
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': 90
            }
            
            response = requests.get(
                'https://api.abuseipdb.com/api/v2/check',
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                result = data.get('data', {})
                
                return {
                    'abuse_confidence_score': result.get('abuseConfidenceScore', 0),
                    'total_reports': result.get('totalReports', 0),
                    'last_reported': result.get('lastReportedAt', 'Never'),
                    'is_public': result.get('isPublic', False),
                    'is_whitelisted': result.get('isWhitelisted', False),
                    'country': result.get('countryCode', 'Unknown')
                }
            else:
                return {'error': f"API returned {response.status_code}"}
                
        except requests.RequestException as e:
            return {'error': f"Request failed: {str(e)}"}
    
    def query_alienvault(self, ip_address):
        """Query AlienVault OTX for threat intelligence"""
        if not self.api_keys['alienvault']:
            return {'error': 'API key not configured'}
        
        try:
            headers = {'X-OTX-API-KEY': self.api_keys['alienvault']}
            response = requests.get(
                f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip_address}/general',
                headers=headers,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                
                return {
                    'pulse_count': data.get('pulse_info', {}).get('count', 0),
                    'related_samples': len(data.get('analysis', {}).get('plugins', {}).get('avast', {}).get('results', [])),
                    'reputation': data.get('reputation', 0),
                    'threat_types': [pulse.get('name', '') for pulse in data.get('pulse_info', {}).get('pulses', [])[:5]]
                }
            else:
                return {'error': f"API returned {response.status_code}"}
                
        except requests.RequestException as e:
            return {'error': f"Request failed: {str(e)}"}
    
    def calculate_reputation_score(self, vt_result, abuse_result, otx_result):
        """Calculate overall reputation score (0-100, higher = more malicious)"""
        score = 0
        
        # VirusTotal weight: 40%
        if 'malicious' in vt_result:
            malicious = vt_result['malicious']
            total = vt_result.get('total_engines', 1)
            vt_score = (malicious / max(total, 1)) * 100
            score += min(vt_score * 0.4, 40)
        
        # AbuseIPDB weight: 40%
        if 'abuse_confidence_score' in abuse_result:
            abuse_score = abuse_result['abuse_confidence_score']
            score += min(abuse_score * 0.4, 40)
        
        # AlienVault weight: 20%
        if 'pulse_count' in otx_result:
            otx_score = min(otx_result['pulse_count'] * 5, 20)  # 5 points per pulse
            score += otx_score
        
        return min(score, 100)
    
    def get_risk_level(self, score):
        """Convert score to risk level"""
        if score >= 80:
            return 'Critical'
        elif score >= 60:
            return 'High'
        elif score >= 40:
            return 'Medium'
        elif score >= 20:
            return 'Low'
        else:
            return 'Very Low'
    
    def extract_threat_tags(self, vt_result, abuse_result, otx_result):
        """Extract threat tags from intelligence data"""
        tags = []
        
        # VirusTotal tags
        if vt_result.get('malicious', 0) > 5:
            tags.append('Multiple AV Detections')
        
        # AbuseIPDB tags
        if abuse_result.get('abuse_confidence_score', 0) > 80:
            tags.append('High Abuse Confidence')
        
        if abuse_result.get('total_reports', 0) > 10:
            tags.append('Frequently Reported')
        
        # AlienVault tags
        if otx_result.get('pulse_count', 0) > 5:
            tags.append('Known Threat Actor')
        
        return tags
    
    def get_fallback_result(self, ip_address):
        """Fallback result when APIs fail"""
        return {
            'ip_address': ip_address,
            'reputation_score': 0,
            'is_malicious': False,
            'risk_level': 'Unknown',
            'sources': {'error': 'All APIs unavailable'},
            'last_updated': datetime.now().isoformat(),
            'tags': ['Intelligence Unavailable']
        }
    
    def get_global_threat_level(self):
        """Get global threat level summary"""
        try:
            # This could query global threat feeds
            return {
                'global_risk_level': 'Elevated',
                'top_threats': ['Ransomware', 'Phishing', 'DDoS'],
                'active_campaigns': 12,
                'last_updated': datetime.now().isoformat()
            }
        except Exception as e:
            return {
                'global_risk_level': 'Unknown',
                'top_threats': [],
                'active_campaigns': 0,
                'last_updated': datetime.now().isoformat()
            }
    
    def bulk_ip_lookup(self, ip_list):
        """Perform bulk IP reputation lookup"""
        results = {}
        for ip in ip_list:
            results[ip] = self.check_ip_reputation(ip)
            time.sleep(0.1)  # Rate limiting
        return results
    
    def get_historical_data(self, ip_address, days=30):
        """Get historical threat data for an IP"""
        # This would typically query a historical database
        return {
            'ip_address': ip_address,
            'analysis_period': f"Last {days} days",
            'total_detections': 0,
            'trend': 'stable',
            'first_seen': datetime.now().isoformat(),
            'last_seen': datetime.now().isoformat()
        }