import os
import json
import time
from datetime import datetime, timedelta

class CacheManager:
    def __init__(self, cache_dir="cache", cache_duration=21600):  # 6 hours in seconds
        self.cache_dir = cache_dir
        self.cache_duration = cache_duration
        
        # Create cache directory if it doesn't exist
        if not os.path.exists(cache_dir):
            os.makedirs(cache_dir)
    
    def _get_cache_path(self, cache_key):
        """Get the path to the cache file for a given key"""
        return os.path.join(self.cache_dir, f"{cache_key}.json")
    
    def get(self, cache_key):
        """Get a value from the cache if it exists and is not expired"""
        cache_path = self._get_cache_path(cache_key)
        
        if not os.path.exists(cache_path):
            return None
        
        try:
            with open(cache_path, 'r') as f:
                cache_data = json.load(f)
                
            # Check if cache is expired
            if time.time() - cache_data['timestamp'] > self.cache_duration:
                # Cache expired, delete it
                os.remove(cache_path)
                return None
                
            return cache_data['value']
        except (json.JSONDecodeError, KeyError, IOError):
            # If there's any error reading the cache, return None
            return None
    
    def set(self, cache_key, value):
        """Set a value in the cache with the current timestamp"""
        cache_path = self._get_cache_path(cache_key)
        
        cache_data = {
            'timestamp': time.time(),
            'value': value
        }
        
        try:
            with open(cache_path, 'w') as f:
                json.dump(cache_data, f)
            return True
        except IOError:
            return False
    
    def clear(self, cache_key=None):
        """Clear the cache for a specific key or all keys"""
        if cache_key:
            cache_path = self._get_cache_path(cache_key)
            if os.path.exists(cache_path):
                os.remove(cache_path)
        else:
            # Clear all cache files
            for filename in os.listdir(self.cache_dir):
                if filename.endswith('.json'):
                    os.remove(os.path.join(self.cache_dir, filename))
    
    def get_expiry_time(self, cache_key):
        """Get the expiry time for a cache entry"""
        cache_path = self._get_cache_path(cache_key)
        
        if not os.path.exists(cache_path):
            return None
        
        try:
            with open(cache_path, 'r') as f:
                cache_data = json.load(f)
                
            expiry_time = cache_data['timestamp'] + self.cache_duration
            return datetime.fromtimestamp(expiry_time)
        except (json.JSONDecodeError, KeyError, IOError):
            return None 