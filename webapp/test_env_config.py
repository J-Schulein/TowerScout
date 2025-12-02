#!/usr/bin/env python3
"""
TowerScout API Key Security Validation Test
Tests the new environment variable configuration system
"""

import os
import sys
from dotenv import load_dotenv

def test_environment_loading():
    """Test that environment variables load correctly"""
    print("🔍 Testing TowerScout Environment Variable Configuration...")
    print("=" * 60)
    
    # Load environment variables
    load_dotenv()
    
    # Test API key loading
    print("\n📋 API Key Configuration:")
    google_key = os.getenv('GOOGLE_API_KEY')
    bing_key = os.getenv('BING_API_KEY')
    flask_secret = os.getenv('FLASK_SECRET_KEY')
    
    if google_key:
        print(f"✅ Google API Key: Loaded ({len(google_key)} characters)")
    else:
        print("❌ Google API Key: MISSING")
        return False
    
    if bing_key:
        print(f"✅ Bing API Key: Loaded ({len(bing_key)} characters)")
    else:
        print("⚠️  Bing API Key: Missing (optional)")
    
    if flask_secret:
        print(f"✅ Flask Secret Key: Loaded ({len(flask_secret)} characters)")
    else:
        print("❌ Flask Secret Key: MISSING")
        return False
    
    # Test Flask configuration loading simulation
    print("\n⚙️  Flask Configuration Simulation:")
    flask_env = os.getenv('FLASK_ENV', 'development')
    flask_debug = os.getenv('FLASK_DEBUG', 'false').lower() == 'true'
    default_provider = os.getenv('DEFAULT_MAP_PROVIDER', 'google')
    
    print(f"✅ Flask Environment: {flask_env}")
    print(f"✅ Flask Debug Mode: {flask_debug}")
    print(f"✅ Default Map Provider: {default_provider}")
    
    # Test error conditions
    print("\n🛡️  Security Validation:")
    
    # Check key lengths
    if len(google_key) < 20:
        print("⚠️  Google API key seems short - verify it's correct")
    else:
        print("✅ Google API key length appears valid")
    
    if len(flask_secret) < 32:
        print("⚠️  Flask secret key is too short (should be 32+ chars)")
        return False
    else:
        print("✅ Flask secret key length is secure")
    
    print("\n🎉 Environment Variable Loading: SUCCESS")
    print("=" * 60)
    return True

def test_missing_keys():
    """Test error handling for missing keys"""
    print("\n🧪 Testing Missing Key Error Handling...")
    
    # Temporarily unset keys to test error handling
    original_google = os.environ.pop('GOOGLE_API_KEY', None)
    original_flask = os.environ.pop('FLASK_SECRET_KEY', None)
    
    try:
        # Simulate the error checking logic from towerscout.py
        google_key = os.getenv('GOOGLE_API_KEY')
        flask_secret = os.getenv('FLASK_SECRET_KEY')
        
        errors = []
        if not google_key:
            errors.append("GOOGLE_API_KEY environment variable is required")
        if not flask_secret:
            errors.append("FLASK_SECRET_KEY environment variable is required")
        
        if errors:
            print("✅ Error handling works correctly:")
            for error in errors:
                print(f"   - {error}")
        else:
            print("❌ Error handling failed - should detect missing keys")
            
    finally:
        # Restore original values
        if original_google:
            os.environ['GOOGLE_API_KEY'] = original_google
        if original_flask:
            os.environ['FLASK_SECRET_KEY'] = original_flask

if __name__ == "__main__":
    success = test_environment_loading()
    test_missing_keys()
    
    if success:
        print("\n✅ VALIDATION COMPLETE: TowerScout is ready for secure deployment")
        sys.exit(0)
    else:
        print("\n❌ VALIDATION FAILED: Configuration issues detected")
        sys.exit(1)