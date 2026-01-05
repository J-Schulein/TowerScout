#!/usr/bin/env python3
"""
Test if the provided key works with Bing Maps instead of Azure Maps
"""

import os
import sys
import requests
from dotenv import load_dotenv

# Load environment variables from webapp directory
load_dotenv('.env')

def test_bing_maps_authentication(key):
    """Test if the key works with Bing Maps API"""
    print(f"🧪 Testing Bing Maps API with key: {key[:10]}...{key[-6:]}")
    print("=" * 60)
    
    # Bing Maps REST API endpoints
    test_endpoints = [
        {
            'name': 'Bing Maps - Geocoding',
            'url': 'http://dev.virtualearth.net/REST/v1/Locations',
            'params': {
                'q': 'Seattle, WA',
                'key': key,
                'o': 'json'
            }
        },
        {
            'name': 'Bing Maps - Imagery Metadata',
            'url': 'http://dev.virtualearth.net/REST/V1/Imagery/Metadata/Aerial',
            'params': {
                'key': key,
                'o': 'json'
            }
        },
        {
            'name': 'Bing Maps - Static Map',
            'url': 'http://dev.virtualearth.net/REST/v1/Imagery/Map/Aerial/Seattle WA',
            'params': {
                'key': key,
                'mapSize': '640,640'
            }
        }
    ]
    
    success_count = 0
    
    for endpoint in test_endpoints:
        print(f"Testing: {endpoint['name']}")
        print(f"URL: {endpoint['url']}")
        
        try:
            response = requests.get(endpoint['url'], params=endpoint['params'], timeout=10)
            print(f"Status Code: {response.status_code}")
            
            if response.status_code == 200:
                print("✅ SUCCESS!")
                success_count += 1
                
                # For JSON responses, check content
                if 'json' in response.headers.get('content-type', '').lower():
                    try:
                        json_data = response.json()
                        if 'resourceSets' in json_data:
                            print(f"   Found {len(json_data['resourceSets'])} resource sets")
                    except:
                        pass
                        
            else:
                print(f"❌ Failed: Status {response.status_code}")
                print(f"   Response: {response.text[:200]}...")
                
        except Exception as e:
            print(f"❌ Exception: {e}")
        
        print()
    
    return success_count

def main():
    subscription_key = os.getenv('AZURE_MAPS_SUBSCRIPTION_KEY')
    
    if not subscription_key:
        print("❌ No Azure Maps subscription key found in environment")
        return
    
    print("🔍 Key Format Analysis")
    print("=" * 60)
    print(f"Key Length: {len(subscription_key)} characters")
    print(f"Key Format: {subscription_key[:15]}...{subscription_key[-10:]}")
    
    # Check if this looks like a Bing Maps key
    if len(subscription_key) > 60 and '-' in subscription_key:
        print("🔍 Key characteristics suggest this might be a Bing Maps API key")
        print("   - Long length (>60 characters)")
        print("   - Contains hyphens")
        print("   - Format: [alphanumeric]-[alphanumeric]-...-[alphanumeric]")
    else:
        print("🔍 Key doesn't match typical Azure Maps subscription key format")
    
    print()
    
    # Test with Bing Maps
    success_count = test_bing_maps_authentication(subscription_key)
    
    print("=" * 60)
    if success_count > 0:
        print(f"✅ SUCCESS: {success_count}/3 Bing Maps endpoints worked!")
        print("🔍 CONCLUSION: This appears to be a valid Bing Maps API key, not Azure Maps")
        print()
        print("💡 SOLUTION: Update TowerScout to use Bing Maps instead of Azure Maps,")
        print("   or obtain a proper Azure Maps subscription key from Azure Portal")
    else:
        print("❌ Key failed authentication with both Azure Maps and Bing Maps")
        print("🔍 CONCLUSION: The API key may be invalid, expired, or from a different service")

if __name__ == "__main__":
    main()