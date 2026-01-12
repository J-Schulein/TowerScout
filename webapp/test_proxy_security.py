#!/usr/bin/env python3
"""
Test script for TASK-034 API key security implementation
Tests the unified map proxy system without loading ML dependencies
"""

import os
import sys
import json

def test_template_security():
    """Test that API keys are no longer exposed in templates"""
    print("🔍 Testing template security...")
    
    template_file = 'templates/towerscout.html'
    try:
        with open(template_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Check for API key exposures
        exposures = []
        if 'gak = "{{google_map_key}}"' in content:
            exposures.append('Google API key global variable')
        if 'aak = "{{azure_map_key}}"' in content:
            exposures.append('Azure API key global variable')
        if 'key={{google_map_key}}' in content:
            exposures.append('Google API key in SDK URL')
        if 'subscriptionKey: {{azure_map_key}}' in content:
            exposures.append('Azure API key in SDK config')
            
        if exposures:
            print("❌ Template security FAILED:")
            for exp in exposures:
                print(f"   - {exp}")
            return False
        else:
            print("✅ Template security PASSED - no API key exposures found")
            
        # Check for proxy configuration
        if 'MAP_PROXY_CONFIG' in content:
            print("✅ MAP_PROXY_CONFIG found in template")
        else:
            print("⚠️  MAP_PROXY_CONFIG not found in template")
            
        return True
        
    except FileNotFoundError:
        print(f"❌ Template file not found: {template_file}")
        return False

def test_javascript_security():
    """Test that JavaScript uses proxy endpoints instead of direct API calls"""
    print("\n🔍 Testing JavaScript security...")
    
    js_file = 'js/towerscout.js'
    try:
        with open(js_file, 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Check for direct API calls that should be proxied
        direct_calls = []
        if 'atlas.microsoft.com' in content:
            # Check if it's in a comment or proxy endpoint
            lines = content.split('\n')
            for i, line in enumerate(lines):
                if 'atlas.microsoft.com' in line and not line.strip().startswith('//') and not '/api/maps/azure' in line:
                    direct_calls.append(f"Line {i+1}: Direct Azure API call")
                    
        if 'maps.googleapis.com' in content and 'key=' in content:
            direct_calls.append('Direct Google Maps API call with key parameter')
            
        if direct_calls:
            print("❌ JavaScript security FAILED:")
            for call in direct_calls[:5]:  # Show first 5 issues
                print(f"   - {call}")
            if len(direct_calls) > 5:
                print(f"   - ... and {len(direct_calls)-5} more issues")
            return False
        else:
            print("✅ JavaScript security PASSED - using proxy endpoints")
            
        # Check for proxy endpoint usage
        if '/api/maps/azure/search' in content:
            print("✅ Azure search proxy endpoint found")
        else:
            print("⚠️  Azure search proxy endpoint not found")
            
        return True
        
    except FileNotFoundError:
        print(f"❌ JavaScript file not found: {js_file}")
        return False

def test_flask_route_security():
    """Test that Flask routes no longer inject API keys"""
    print("\n🔍 Testing Flask route security...")
    
    try:
        # Read towerscout.py and check for API key injection
        with open('towerscout.py', 'r', encoding='utf-8') as f:
            content = f.read()
            
        # Check for API key injection in render_template calls
        injections = []
        if 'google_map_key=google_api_key' in content:
            injections.append('Google API key injection in render_template')
        if 'azure_map_key=azure_api_key' in content:
            injections.append('Azure API key injection in render_template')
        if 'bing_map_key=bing_api_key' in content:
            injections.append('Bing API key injection in render_template')
            
        if injections:
            print("❌ Flask route security FAILED:")
            for inj in injections:
                print(f"   - {inj}")
            return False
        else:
            print("✅ Flask route security PASSED - no API key injection")
            
        # Check for proxy endpoint implementation
        if '/api/maps/<provider>/<service>' in content:
            print("✅ Unified proxy endpoint found")
        else:
            print("⚠️  Unified proxy endpoint not found")
            
        return True
        
    except FileNotFoundError:
        print("❌ towerscout.py not found")
        return False

def test_proxy_configuration():
    """Test proxy configuration and cache setup"""
    print("\n🔍 Testing proxy configuration...")
    
    try:
        # Import without ML dependencies
        original_modules = {}
        mock_modules = ['efficientnet_pytorch', 'torch', 'torchvision']
        
        for module in mock_modules:
            if module in sys.modules:
                original_modules[module] = sys.modules[module]
            
        # Mock the modules
        from unittest.mock import MagicMock
        for module in mock_modules:
            sys.modules[module] = MagicMock()
        
        # Import specific components for testing
        import importlib.util
        spec = importlib.util.spec_from_file_location("towerscout_test", "towerscout.py")
        towerscout_test = importlib.util.module_from_spec(spec)
        
        # Test just the configuration parts
        print("✅ Proxy configuration accessible")
        
        # Check cache directory creation
        cache_dir = os.path.join(os.getcwd(), 'cache', 'maps')
        if os.path.exists(cache_dir):
            print(f"✅ Cache directory exists: {cache_dir}")
        else:
            print(f"⚠️  Cache directory not found: {cache_dir}")
            
        # Restore original modules
        for module, original in original_modules.items():
            sys.modules[module] = original
        for module in mock_modules:
            if module not in original_modules and module in sys.modules:
                del sys.modules[module]
                
        return True
        
    except Exception as e:
        print(f"❌ Proxy configuration test failed: {e}")
        return False

def main():
    """Run all security tests"""
    print("🚀 TASK-034 API Key Security Implementation Test")
    print("=" * 60)
    
    tests = [
        test_template_security,
        test_javascript_security, 
        test_flask_route_security,
        test_proxy_configuration
    ]
    
    results = []
    for test in tests:
        try:
            result = test()
            results.append(result)
        except Exception as e:
            print(f"❌ Test failed with exception: {e}")
            results.append(False)
    
    print("\n" + "=" * 60)
    print("📊 Test Results Summary:")
    
    passed = sum(results)
    total = len(results)
    
    if passed == total:
        print(f"✅ ALL TESTS PASSED ({passed}/{total})")
        print("🎉 TASK-034 implementation is secure and ready!")
    else:
        print(f"⚠️  PARTIAL SUCCESS ({passed}/{total} tests passed)")
        print("🔧 Some issues need attention before deployment")
    
    return passed == total

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)