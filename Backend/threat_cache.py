# cache.py or threat_cache.py
import time
from collections import defaultdict
from datetime import datetime, timedelta

class ThreatCache:
    def __init__(self, max_size=1000, ttl=3600):
        self.cache = {}
        self.max_size = max_size
        self.ttl = ttl  # Time to live in seconds
        self.access_patterns = defaultdict(int)
    
    def get(self, key):
        """Get item from cache if not expired"""
        if key in self.cache:
            item = self.cache[key]
            if time.time() - item['timestamp'] < self.ttl:
                self.access_patterns[key] += 1
                return item['data']
            else:
                # Remove expired item
                del self.cache[key]
                if key in self.access_patterns:
                    del self.access_patterns[key]
        return None
    
    def set(self, key, data):
        """Add item to cache with timestamp"""
        # Evict if cache is full
        if len(self.cache) >= self.max_size:
            self._evict_least_used()
        
        self.cache[key] = {
            'data': data,
            'timestamp': time.time()
        }
    
    def _evict_least_used(self):
        """Evict least frequently used items"""
        if not self.access_patterns:
            # If no access patterns, remove oldest
            oldest_key = next(iter(self.cache))
            del self.cache[oldest_key]
            return
        
        # Find least used key
        least_used_key = min(self.access_patterns, key=self.access_patterns.get)
        if least_used_key in self.cache:
            del self.cache[least_used_key]
        if least_used_key in self.access_patterns:
            del self.access_patterns[least_used_key]
    
    def clear_expired(self):
        """Clear all expired cache entries"""
        current_time = time.time()
        expired_keys = [
            key for key, item in self.cache.items()
            if current_time - item['timestamp'] >= self.ttl
        ]
        for key in expired_keys:
            del self.cache[key]
            if key in self.access_patterns:
                del self.access_patterns[key]
    
    def cache_threat_patterns(self, patterns):
        """Cache threat patterns with fingerprint as key"""
        if not patterns:
            return
        
        for pattern in patterns:
            pattern_hash = self._generate_pattern_hash(pattern)
            self.set(f"pattern_{pattern_hash}", pattern)
    
    def _generate_pattern_hash(self, pattern):
        """Generate hash for threat pattern"""
        import hashlib
        pattern_str = str(pattern).encode('utf-8')
        return hashlib.md5(pattern_str).hexdigest()
    
    def get_cached_patterns(self):
        """Get all cached threat patterns"""
        patterns = []
        for key in list(self.cache.keys()):
            if key.startswith('pattern_'):
                pattern = self.get(key)
                if pattern:
                    patterns.append(pattern)
        return patterns
    
    def get_stats(self):
        """Get cache statistics"""
        return {
            'total_items': len(self.cache),
            'max_size': self.max_size,
            'ttl_seconds': self.ttl,
            'access_patterns_count': len(self.access_patterns)
        }