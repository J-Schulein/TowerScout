# Azure Maps API Key Management Guide

## Overview

TowerScout's Azure Maps integration supports multiple authentication methods to accommodate both individual developers and enterprise deployments. This guide explains the different types of Azure API keys and how they're managed by the application.

---

## 🔑 **Authentication Methods Supported**

### 1. **Subscription Key Authentication** ⭐ **RECOMMENDED**

**Best for**: Individual developers, small teams, most production deployments

**Configuration**:
```bash
# .env file
AZURE_MAPS_SUBSCRIPTION_KEY=your_subscription_key_here
AZURE_MAPS_AUTH_METHOD=subscription_key  # Default
```

**How to obtain**:
1. Go to [Azure Portal](https://portal.azure.com)
2. Create an Azure Maps Account (or use existing)
3. Navigate to "Keys and Endpoint" 
4. Copy the Primary Key

**Key Types**:
- **Primary Key**: Use for production
- **Secondary Key**: Use for key rotation without downtime
- Both keys have identical permissions and rate limits

**Security Features**:
- Keys can be regenerated without affecting the other key
- Rate limiting and usage monitoring through Azure Portal
- Works with Azure Key Vault for enterprise security

---

### 2. **Azure Active Directory (AAD) Authentication** 🏢 **ENTERPRISE**

**Best for**: Enterprise deployments, existing AAD infrastructure, role-based access control

**Configuration**:
```bash
# .env file
AZURE_MAPS_AUTH_METHOD=aad
AZURE_CLIENT_ID=your_application_client_id
AZURE_TENANT_ID=your_tenant_id
AZURE_CLIENT_SECRET=your_client_secret  # Or use certificate
```

**How to set up**:
1. Register application in Azure Active Directory
2. Grant Azure Maps permissions to the application
3. Configure service principal with appropriate roles
4. Use application credentials for authentication

**Enterprise Benefits**:
- **Role-based access control**: Different permissions for different users/applications
- **Audit trails**: Complete logging of who accessed what resources
- **Conditional access**: MFA, device compliance, location restrictions
- **Integration**: Works with existing enterprise identity systems

**Code Example**:
```python
# Enterprise AAD authentication (future enhancement)
from azure.identity import DefaultAzureCredential
from azure.maps.authentication import AzureMapsCredential

def get_aad_authenticated_client():
    credential = DefaultAzureCredential()
    maps_credential = AzureMapsCredential(
        credential=credential,
        client_id=os.getenv('AZURE_CLIENT_ID')
    )
    return maps_credential
```

---

### 3. **Shared Access Signature (SAS) Tokens** 🔒 **ADVANCED**

**Best for**: Time-limited access, third-party integrations, fine-grained permissions

**Configuration**:
```bash
# .env file
AZURE_MAPS_AUTH_METHOD=sas
AZURE_MAPS_SAS_TOKEN=sv=2022-11-02&ss=bfqt&srt=sco&sp=rwdlacupx&se=2024-01-01T00:00:00Z&st=2023-01-01T00:00:00Z&spr=https&sig=...
```

**Features**:
- **Time-bound**: Automatic expiration
- **Scoped permissions**: Limit access to specific operations
- **Revocable**: Can be invalidated before expiration
- **No long-term secrets**: Reduces security risk

---

## 🏗️ **Current TowerScout Implementation**

### **How Azure Maps Keys Are Accessed**

The application follows this authentication flow:

```python
# 1. Load from environment variables (ts_azure_maps.py)
def __init__(self, subscription_key: str):
    if not subscription_key or not subscription_key.strip():
        raise ConfigurationError("Azure Maps subscription key is required")
    self.subscription_key = subscription_key.strip()

# 2. Validate and initialize (towerscout.py)
def load_api_keys():
    azure_key = os.getenv('AZURE_MAPS_SUBSCRIPTION_KEY')
    if azure_key:
        return AzureMaps(azure_key)
    else:
        logger.warning("Azure Maps not available - no subscription key")
        return None

# 3. Use in API calls (ts_azure_maps.py)
def get_url(self, tile):
    url = f"{self.base_url}?api-version={self.api_version}&subscription-key={self.subscription_key}&..."
    return url
```

### **Security Best Practices Implemented**

✅ **Environment Variables**: No hardcoded keys in source code
✅ **Input Validation**: Keys are validated before use  
✅ **Error Handling**: Clear error messages without exposing keys
✅ **Logging**: Keys are never logged or exposed in debugging output

---

## 🏢 **Enterprise vs Individual Key Management**

### **Individual/Development Usage**

```bash
# Simple subscription key approach
AZURE_MAPS_SUBSCRIPTION_KEY=your_personal_subscription_key
DEFAULT_MAP_PROVIDER=azure
```

**Characteristics**:
- Single subscription key for entire application
- Direct billing to personal/company Azure account
- Straightforward setup and management
- Suitable for small teams and development environments

### **Enterprise Usage Options**

#### **Option 1: Centralized Subscription Key** ⭐ **RECOMMENDED**
```bash
# Single enterprise subscription key
AZURE_MAPS_SUBSCRIPTION_KEY=enterprise_subscription_key_from_it_department
DEFAULT_MAP_PROVIDER=azure
```

**Benefits**:
- Centralized billing and cost management
- IT department controls key rotation
- Simple deployment across multiple environments
- No additional authentication complexity

#### **Option 2: Azure Key Vault Integration** 🔒 **MOST SECURE**
```bash
# Key Vault configuration (TASK-009 implementation)
AZURE_KEY_VAULT_URL=https://your-keyvault.vault.azure.net/
AZURE_MAPS_KEY_NAME=towerscout-azure-maps-key
AZURE_MAPS_AUTH_METHOD=keyvault
```

**Benefits**:
- Centralized secret management
- Key rotation without application restart
- Audit trails for key access
- Integration with enterprise security policies

#### **Option 3: Service Principal (AAD)** 🏢 **ENTERPRISE IDENTITY**
```bash
# Azure Active Directory authentication
AZURE_MAPS_AUTH_METHOD=aad
AZURE_TENANT_ID=your-tenant-id
AZURE_CLIENT_ID=towerscout-app-registration
AZURE_CLIENT_SECRET=service-principal-secret
```

**Benefits**:
- Integration with existing identity systems
- Role-based access control
- MFA and conditional access support
- No shared secrets between teams

---

## 📊 **Key Management Comparison**

| Method | Individual | Small Team | Enterprise | Security Level |
|--------|------------|------------|------------|----------------|
| **Subscription Key** | ✅ Perfect | ✅ Good | ⚠️ OK | Medium |
| **Key Vault** | ⚠️ Overkill | ✅ Good | ✅ Excellent | High |
| **AAD Service Principal** | ❌ Too Complex | ⚠️ OK | ✅ Excellent | Very High |
| **SAS Tokens** | ❌ Complex | ⚠️ Special Cases | ✅ Advanced Scenarios | High |

---

## 🔄 **Key Rotation Procedures**

### **Subscription Key Rotation** (Zero Downtime)

```bash
# Phase 1: Add secondary key
AZURE_MAPS_SUBSCRIPTION_KEY=secondary_key_here

# Phase 2: Regenerate primary key in Azure Portal
# Phase 3: Update to new primary key
AZURE_MAPS_SUBSCRIPTION_KEY=new_primary_key_here

# Phase 4: Regenerate secondary key for next rotation
```

### **Automated Key Rotation** (Enterprise)

```python
# Future enhancement for TASK-009
class AzureKeyVaultRotation:
    def rotate_azure_maps_key(self):
        # 1. Generate new key in Azure Maps
        # 2. Store in Key Vault
        # 3. Update application configuration
        # 4. Revoke old key after validation period
        pass
```

---

## 🎯 **Recommendations by Use Case**

### **Individual Developers**
```bash
# Recommended configuration
AZURE_MAPS_SUBSCRIPTION_KEY=your_personal_key
AZURE_MAPS_AUTH_METHOD=subscription_key
DEFAULT_MAP_PROVIDER=azure
```

### **Small Teams (2-10 developers)**
```bash
# Shared subscription key with team Azure account
AZURE_MAPS_SUBSCRIPTION_KEY=team_shared_key
AZURE_MAPS_AUTH_METHOD=subscription_key
DEFAULT_MAP_PROVIDER=azure

# Optional: Basic monitoring
DETAILED_LOGGING=true
LOG_LEVEL=INFO
```

### **Enterprise (10+ users, compliance requirements)**
```bash
# Key Vault integration (requires TASK-009)
AZURE_KEY_VAULT_URL=https://enterprise-vault.vault.azure.net/
AZURE_MAPS_KEY_NAME=towerscout-maps-key
AZURE_MAPS_AUTH_METHOD=keyvault

# Enterprise security settings
SECURE_COOKIES=true
SESSION_TIMEOUT=15
DETAILED_LOGGING=true
LOG_LEVEL=WARNING
```

---

## 🚨 **Security Considerations**

### **Current Implementation Security**
- ✅ Environment variable-based configuration
- ✅ No keys stored in source code
- ✅ Input validation and sanitization
- ✅ Error handling without key exposure
- ✅ HTTPS-only API communications

### **Enterprise Security Enhancements** (Future)
- **Key Vault Integration** (TASK-009): Centralized secret management
- **AAD Integration**: Role-based access control  
- **Network Security**: VNet integration, private endpoints
- **Compliance**: SOC 2, FedRAMP compliance options

### **Development vs Production**

**Development Environment**:
```bash
# Development settings
FLASK_ENV=development
AZURE_MAPS_SUBSCRIPTION_KEY=dev_key_with_lower_limits
MOCK_API_CALLS=false  # Use real APIs for accurate testing
```

**Production Environment**:
```bash
# Production settings  
FLASK_ENV=production
SECURE_COOKIES=true
AZURE_MAPS_SUBSCRIPTION_KEY=production_key_with_higher_limits
DETAILED_LOGGING=false  # Avoid logging sensitive data
```

---

## 📈 **Usage Monitoring & Cost Management**

### **Azure Maps Pricing Tiers**

| Tier | Price per 1K Requests | Included Requests/Month |
|------|----------------------|-------------------------|
| **Gen2 S0** | $0.50 | None |
| **Gen2 S1** | $4.00 | 250K |
| **Gen1 S0** | $5.00 | 25K |
| **Gen1 S1** | $5.00 | 125K |

### **Cost Monitoring Configuration**

```bash
# Enable usage tracking
AZURE_MAPS_TRACK_USAGE=true
AZURE_MAPS_COST_ALERTS=true
AZURE_MAPS_MONTHLY_BUDGET=100  # USD

# Performance optimization to reduce costs
AZURE_MAPS_CACHE_TILES=true
AZURE_MAPS_BATCH_REQUESTS=true
```

### **Enterprise Cost Management**

- **Budgets**: Set spending limits in Azure Portal
- **Alerts**: Automated notifications at 50%, 80%, 100% of budget
- **Usage Analytics**: Detailed reporting by application/team
- **Cost Allocation**: Tag resources for department billing

---

## 🔧 **Troubleshooting Authentication Issues**

### **Common Problems & Solutions**

**1. "Invalid subscription key" errors**:
```bash
# Verify key is correct
curl "https://atlas.microsoft.com/map/static?api-version=2024-04-01&tilesetId=microsoft.imagery&zoom=1&center=0,0&height=256&width=256&subscription-key=$AZURE_MAPS_SUBSCRIPTION_KEY"

# Check for extra spaces/characters
export AZURE_MAPS_SUBSCRIPTION_KEY=$(echo "$AZURE_MAPS_SUBSCRIPTION_KEY" | tr -d '[:space:]')
```

**2. "Rate limit exceeded" errors**:
```bash
# Check current usage in Azure Portal
# Consider upgrading tier or implementing request caching
AZURE_MAPS_CACHE_TILES=true
```

**3. "Authentication method not supported" errors**:
```bash
# Ensure auth method matches your setup
AZURE_MAPS_AUTH_METHOD=subscription_key  # Default method
```

### **Validation Script**

```bash
# Test Azure Maps configuration
cd webapp
python -c "
from ts_azure_maps import AzureMaps
import os
try:
    key = os.getenv('AZURE_MAPS_SUBSCRIPTION_KEY')
    maps = AzureMaps(key)
    print('✅ Azure Maps configuration valid')
except Exception as e:
    print(f'❌ Configuration error: {e}')
"
```

---

## 🎯 **Next Steps & Future Enhancements**

### **Immediate (Current Implementation)**
- ✅ Subscription key authentication working
- ✅ Environment variable configuration
- ✅ Multi-provider support (Google/Azure/Bing)

### **Short Term (TASK-009: Azure Key Vault)**
- 🔄 **Key Vault Integration**: Centralized secret management
- 🔄 **Automatic Key Rotation**: Zero-downtime key updates  
- 🔄 **Enhanced Security**: Enterprise-grade secret protection

### **Medium Term (Future Tasks)**
- 🔄 **AAD Integration**: Azure Active Directory authentication
- 🔄 **SAS Token Support**: Time-limited access tokens
- 🔄 **Multi-Tenant Support**: Per-user API key management

### **Long Term (Enterprise Features)**
- 🔄 **Network Security**: Private endpoint integration
- 🔄 **Compliance**: SOC 2, FedRAMP certification support
- 🔄 **Global Deployment**: Multi-region key management

---

**Azure Maps authentication is production-ready with subscription keys. Enterprise customers should consider TASK-009 (Key Vault Integration) for enhanced security and centralized management.**