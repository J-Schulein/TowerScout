# TowerScout Local Deployment Technical Design

## Executive Summary

This document outlines the technical architecture and implementation strategy for transforming TowerScout from a student prototype into a **locally-deployable, user-friendly application**. The design follows simplified architecture patterns optimized for single-user deployment on individual devices.

**Architecture Philosophy**: Local deployment optimization with user experience focus, eliminating enterprise complexity while maintaining ML model integrity.

**DEPLOYMENT MODEL UPDATE**: **LOCAL DEPLOYMENT** - TowerScout deployed on individual user devices (epidemiologists, researchers, health departments) rather than hosted service. This fundamentally changes architecture priorities from enterprise security and scalability to installation simplicity and broad hardware compatibility.

**SECURITY MODEL CLARIFICATION**: **LOCAL DEPLOYMENT SECURITY** differs from enterprise models:
- **Physical Access Control**: Primary security boundary is device physical access
- **API Key Protection**: Keys stored in environment variables, but **client-side exposure remains a vulnerability**
- **Network Security**: HTTPS recommended but not enforced for local deployment
- **Authentication**: No user authentication required for single-user local deployment

**CRITICAL SECURITY ISSUE**: Despite security-first claims, API keys are still exposed in client-side JavaScript, visible in browser developer tools. This requires immediate attention (TASK-034).

**IMPLEMENTATION STATUS**: Security foundation complete (10 of 27 original tasks - 37%), Azure Maps migration operational. Sprint 2 (Feb 4-18) nearly complete with memory management, geocoding fixes, visual consistency, and interactive UI enhancements delivered.

**Current Architecture**: Multi-provider map system (Google/Azure), comprehensive error handling infrastructure, and production-ready validation framework **SIMPLIFIED** for local deployment.

---

## 🏗️ SYSTEM ARCHITECTURE

### Current Architecture Analysis

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Flask Web     │    │   Map Providers  │    │   ML Detection  │
│   Application   │◄──►│ (Google/Azure)   │    │   Pipeline      │
│   (towerscout.py)│    │                  │    │ (YOLOv5/EfficNet)│
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                        │                        │
         ▼                        ▼                        ▼
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Session       │    │   Image          │    │   Model         │
│   Management    │    │   Processing     │    │   Parameters    │
│   (Flask)       │    │   (ts_imgutil)   │    │   (Protected)   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

### Local Deployment Target Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Local User Interface Layer                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   Web Interface   │  │   Setup Wizard   │  │   Settings Page  │  │
│  │   (Enhanced UX)   │  │   (NEW - API     │  │   (NEW - Config  │  │
│  │                 │  │   Key Setup)     │  │   Management)    │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                 Local Application Service Layer                  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   Basic Config   │  │   User-Friendly  │  │   Hardware      │  │
│  │   Service        │  │   Error          │  │   Detection     │  │
│  │   (SIMPLIFIED)   │  │   Handling       │  │   (NEW)         │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│               Core Layer (Protected - Unchanged)                │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   Map Provider   │  │   ML Detection   │  │   Image         │  │
│  │   Abstraction    │  │   Pipeline       │  │   Processing    │  │
│  │   (Google/Azure) │  │   (UNCHANGED)    │  │   (Enhanced)    │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│             Local Infrastructure Layer (Simplified)             │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   Basic Error    │  │   Simple         │  │   File-based     │  │
│  │   Management     │  │   Logging        │  │   Configuration  │  │
│  │   (Completed)    │  │   (Simplified)   │  │   (.env files)   │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

**Key Differences from Enterprise Architecture**:
- **Authentication removed**: Physical access control sufficient for local deployment
- **Configuration simplified**: File-based `.env` configuration instead of enterprise key management
- **User interface enhanced**: Setup wizard and settings management for non-technical users
- **Hardware detection added**: CPU/GPU/MPS detection for diverse local hardware
- **Error handling user-focused**: Non-technical error messages replace technical diagnostics

---

## �️ LOCAL DEPLOYMENT ARCHITECTURE

### Setup Wizard Integration

```python
# Simple Configuration Service for Local Deployment
class LocalConfigurationService:
    def __init__(self):
        self.config_file = '.env'
        
    def setup_wizard_flow(self) -> Dict[str, str]:
        """Guide users through API key setup"""
        return {
            'google_maps': self.validate_google_key(),
            'azure_maps': self.validate_azure_key(),
            'flask_secret': self.generate_secret_key()
        }
    
    def save_configuration(self, config: Dict[str, str]) -> bool:
        """Write configuration to .env file with proper permissions"""
        pass
    
    def test_provider_connectivity(self, provider: str, api_key: str) -> ValidationResult:
        """Real-time API key validation for setup wizard"""
        pass
```

### Hardware Detection Service

```python
# Hardware Compatibility Detection
class HardwareDetectionService:
    def __init__(self):
        self.platform = self._detect_platform()
        self.capabilities = self._detect_capabilities()
    
    def _detect_platform(self) -> Platform:
        """Detect AMD64, ARM64, Apple Silicon"""
        if platform.machine() == 'arm64' and sys.platform == 'darwin':
            return Platform.APPLE_SILICON
        elif platform.machine() in ['aarch64', 'arm64']:
            return Platform.ARM64
        else:
            return Platform.AMD64
    
    def _detect_capabilities(self) -> HardwareCapabilities:
        """Detect GPU, MPS, memory constraints"""
        capabilities = HardwareCapabilities()
        
        # GPU detection
        if torch.cuda.is_available():
            capabilities.gpu = True
            capabilities.gpu_memory = torch.cuda.get_device_properties(0).total_memory
        
        # Apple Silicon MPS detection
        if hasattr(torch.backends, 'mps') and torch.backends.mps.is_available():
            capabilities.mps = True
        
        # Memory detection
        capabilities.system_memory = psutil.virtual_memory().total
        
        return capabilities
    
    def get_optimal_batch_size(self) -> int:
        """Platform-specific batch size optimization"""
        if self.capabilities.gpu and self.capabilities.gpu_memory > 8 * 1024**3:
            return 16  # High-end GPU
        elif self.capabilities.gpu:
            return 8   # Standard GPU
        elif self.capabilities.mps:
            return 6   # Apple Silicon MPS
        elif self.platform == Platform.ARM64:
            return 4   # ARM64 CPU
        else:
            return 4   # AMD64 CPU
```

### User-Friendly Error Service

```python
# Simplified Error Handling for End Users
class UserFriendlyErrorService:
    def __init__(self):
        self.error_templates = self._load_error_templates()
        self.troubleshooting_guide = self._load_troubleshooting_guide()
    
    def transform_technical_error(self, error: Exception) -> UserFriendlyError:
        """Convert technical errors to actionable user guidance"""
        if isinstance(error, ConnectionError):
            return UserFriendlyError(
                title="Network Connection Issue",
                description="TowerScout can't connect to map services",
                solutions=[
                    "Check your internet connection",
                    "Verify your API keys in Settings",
                    "Try a different map provider (Google vs Azure)"
                ],
                test_action="Test Configuration"
            )
        elif isinstance(error, AuthenticationError):
            return UserFriendlyError(
                title="API Key Problem",
                description="Your map provider API key isn't working",
                solutions=[
                    "Check if you copied the API key correctly",
                    "Verify the key has proper permissions",
                    "Make sure billing is enabled for your account"
                ],
                test_action="Test API Key"
            )
        # ... more error patterns
```

---

## ⚠️ ERROR HANDLING ARCHITECTURE

### Overview
TowerScout implements a comprehensive error handling system providing structured error responses, robust logging, and graceful degradation for all external operations.

### Exception Hierarchy

```python
# Base Exception with Structured Details
class TowerScoutError(Exception):
    def __init__(self, message: str, error_code: str = None, 
                 details: Dict[str, Any] = None, user_message: str = None):
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}
        self.user_message = user_message or "An error occurred."
        self.timestamp = datetime.utcnow().isoformat() + "Z"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "error": True,
            "type": self.__class__.__name__,
            "message": self.user_message,
            "technical_message": self.message,
            "timestamp": self.timestamp,
            "details": self.details
        }

# Specialized Exception Classes
ConfigurationError    # Missing API keys, invalid settings
ModelLoadError       # ML model loading failures, GPU issues  
MapProviderError     # Rate limits, authentication, network issues
ProcessingError      # Image processing, detection failures
NetworkError         # Connection timeouts, DNS failures
ResourceError        # Disk space, memory limitations
SessionError         # Session management issues
```

### Logging Architecture

```python
# Multi-Level Structured Logging
class TowerScoutLogger:
    # Application logs (10MB, 5 backups)
    # Error logs (10MB, 10 backups) 
    # Performance logs (5MB, 3 backups, JSON format)
    
    # Component-Specific Loggers:
    get_main_logger()    # General application events
    get_api_logger()     # Flask routes and API calls  
    get_ml_logger()      # Model loading and inference
    get_maps_logger()    # Map provider operations
```

### Network Resilience

```python
# Retry Logic with Exponential Backoff
- Rate Limit Handling: Respect Retry-After headers
- Server Error Recovery: Exponential backoff for 5xx errors
- Circuit Breaker: Prevent cascade failures
- Graceful Degradation: Continue processing when possible
```

### Flask Error Middleware

```python
# Standardized JSON Error Responses
@app.errorhandler(TowerScoutError)
def handle_towerscout_error(error):
    response = jsonify(error.to_dict())
    response.status_code = 400 if isinstance(error, ValidationError) else 500
    return response

# Request/Response Logging for Audit Trail
@app.before_request / @app.after_request
```

---

## 🏛️ COMPONENT ARCHITECTURE

### Map Provider Abstraction (Enhanced)

```python
# Enhanced Map Provider Interface
class MapProvider(ABC):
    @abstractmethod
    def get_tile_url(self, tile: TileInfo) -> str:
        pass
    
    @abstractmethod
    def download_tile(self, url: str) -> TileResult:
        pass
    
    @abstractmethod
    def validate_api_key(self) -> bool:
        pass
    
    @abstractmethod
    def get_usage_limits(self) -> UsageLimits:
        pass
    
    @abstractmethod
    def transform_coordinates(self, lat: float, lng: float) -> Tuple[float, float]:
        """Handle provider-specific coordinate transformations"""
        pass

# Azure Maps Implementation
class AzureMapsProvider(MapProvider):
    def __init__(self, subscription_key: str):
        self.subscription_key = subscription_key
        self.base_url = "https://atlas.microsoft.com/map/static"
    
    def get_tile_url(self, tile: TileInfo) -> str:
        # Azure Maps uses lng,lat order (GeoJSON standard)
        return f"{self.base_url}?api-version=2024-04-01&tilesetId=microsoft.imagery&zoom={tile.zoom}&center={tile.lng},{tile.lat}&width=640&height=640&subscription-key={self.subscription_key}"
    
    def transform_coordinates(self, lat: float, lng: float) -> Tuple[float, float]:
        # Azure Maps uses lng,lat order - return as (lng, lat)
        return (lng, lat)
```

### Coordinate System Handling

```python
# Coordinate Transformation Service
class CoordinateTransformService:
    @staticmethod
    def validate_coordinates(lat: float, lng: float) -> bool:
        """Validate coordinate ranges"""
        return -90 <= lat <= 90 and -180 <= lng <= 180
    
    @staticmethod
    def transform_for_provider(provider: str, lat: float, lng: float) -> Tuple[float, float]:
        """Transform coordinates based on provider requirements"""
        if provider == "azure":
            return (lng, lat)  # Azure Maps uses lng,lat order
        elif provider == "google":
            return (lat, lng)  # Google Maps uses lat,lng order
        else:
            raise ValueError(f"Unknown provider: {provider}")
    
    @staticmethod
    def validate_polygon_accuracy(polygon_coords: List[Tuple[float, float]], 
                                provider_results: Dict[str, Any]) -> ValidationResult:
        """Validate that polygon coordinates produce consistent results across providers"""
        # Implementation for cross-provider validation
        pass

### Error Handling System

```python
# Structured Error Handling
class TowerScoutError(Exception):
    def __init__(self, message: str, error_code: str, details: dict = None):
        self.message = message
        self.error_code = error_code
        self.details = details or {}
        super().__init__(message)

class ErrorHandler:
    def __init__(self, logger: Logger):
        self.logger = logger
    
    def handle_api_error(self, error: Exception, context: dict) -> ErrorResponse:
        # Log and format API errors for user consumption
        pass
    
    def handle_ml_error(self, error: Exception, context: dict) -> ErrorResponse:
        # Handle ML pipeline errors
        pass
```

### Logging Infrastructure

```python
# Structured Logging Configuration
import logging
from logging.handlers import RotatingFileHandler

class LoggingService:
    def __init__(self):
        self.setup_logging()
    
    def setup_logging(self):
        formatter = logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        
        # File handler with rotation
        file_handler = RotatingFileHandler(
            'logs/towerscout.log', maxBytes=10485760, backupCount=5
        )
        file_handler.setFormatter(formatter)
        
        # Configure root logger
        logging.getLogger().addHandler(file_handler)
        logging.getLogger().setLevel(logging.INFO)
```

---

## 🎨 USER INTERFACE ARCHITECTURE

### Frontend Architecture

```javascript
// Enhanced JavaScript Architecture
class TowerScoutUI {
    constructor() {
        this.mapInterface = new MapInterface();
        this.progressTracker = new ProgressTracker();
        this.errorHandler = new UIErrorHandler();
    }
    
    initializeInterface() {
        this.setupEventListeners();
        this.loadConfiguration();
        this.initializeMap();
    }
}

class ProgressTracker {
    showProgress(operation, percentage) {
        // Enhanced progress indication with cancellation
    }
    
    handleCancellation(operationId) {
        // User-initiated operation cancellation
    }
}
```

### Responsive Design Strategy

```css
/* Mobile-First Responsive Design */
.towerscout-interface {
    display: grid;
    grid-template-areas: 
        "header"
        "controls"
        "map"
        "results";
    gap: 1rem;
}

@media (min-width: 768px) {
    .towerscout-interface {
        grid-template-areas: 
            "header header"
            "controls map"
            "results results";
        grid-template-columns: 300px 1fr;
    }
}
```

---

## 📊 DATA FLOW ARCHITECTURE

### Request Processing Pipeline

```
User Request → Input Validation → Processing → Response
      ↓              ↓              ↓           ↓
   Logging       Error Handler  Core Logic   Format
```

### ML Detection Pipeline (Protected)

```
Polygon Input → Tile Generation → Image Download → ML Detection → Result Processing
      ↓               ↓                ↓              ↓              ↓
  Validation      Optimization    Error Handling  GPU/CPU Queue   Formatting
```

### Session Management

```python
# Enhanced Session Architecture
class SessionManager:
    def __init__(self):
        self.session_store = SecureSessionStore()
        self.cleanup_scheduler = SessionCleanupScheduler()
    
    def create_session(self, user_id: str) -> Session:
        session = Session(
            user_id=user_id,
            created_at=datetime.utcnow(),
            temp_directory=self._create_temp_directory()
        )
        return self.session_store.save(session)
    
    def cleanup_expired_sessions(self):
        # Automatic cleanup of expired sessions and temp files
        pass
```

---

## 🔧 CONFIGURATION ARCHITECTURE

### Environment-Based Configuration

```python
# Configuration Management
class Configuration:
    def __init__(self):
        self.load_environment_config()
        self.validate_configuration()
    
    def load_environment_config(self):
        self.google_api_key = os.getenv('GOOGLE_API_KEY')
        self.azure_maps_key = self._get_azure_maps_key()
        self.azure_key_vault_url = os.getenv('AZURE_KEY_VAULT_URL')
        self.flask_secret_key = os.getenv('FLASK_SECRET_KEY')
        self.log_level = os.getenv('LOG_LEVEL', 'INFO')
        self.max_tiles = int(os.getenv('MAX_TILES', '100000'))
    
    def _get_azure_maps_key(self) -> str:
        """Get Azure Maps key from Key Vault or environment"""
        # Try Key Vault first if configured
        if os.getenv('AZURE_KEY_VAULT_URL'):
            try:
                from azure.keyvault.secrets import SecretClient
                from azure.identity import DefaultAzureCredential
                
                credential = DefaultAzureCredential()
                client = SecretClient(
                    vault_url=os.getenv('AZURE_KEY_VAULT_URL'),
                    credential=credential
                )
                secret = client.get_secret('azure-maps-subscription-key')
                return secret.value
            except Exception as e:
                print(f"Key Vault unavailable, falling back to environment: {e}")
        
        return os.getenv('AZURE_MAPS_SUBSCRIPTION_KEY')
    
    def validate_configuration(self):
        required_configs = ['GOOGLE_API_KEY', 'FLASK_SECRET_KEY']
        missing = [k for k in required_configs if not getattr(self, k.lower())]
        if missing:
            raise ConfigurationError(f"Missing required configuration: {missing}")
```

### Runtime Configuration Interface

```python
# Web-based Configuration Management
@app.route('/admin/config', methods=['GET', 'POST'])
@require_admin
def manage_configuration():
    if request.method == 'POST':
        # Update configuration with validation
        pass
    
    return render_template('admin/configuration.html', config=current_config)
```

---

## 🚀 DEPLOYMENT ARCHITECTURE

### Docker Containerization

```dockerfile
# Production Dockerfile Strategy
FROM python:3.12-slim AS base

# Security: Don't run as root
RUN useradd --create-home --shell /bin/bash app
USER app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY --chown=app:app . /app
WORKDIR /app

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s \
    CMD curl -f http://localhost:5000/health || exit 1

EXPOSE 5000
CMD ["python", "towerscout.py"]
```

### Health Monitoring

```python
# Health Check Endpoints
@app.route('/health')
def health_check():
    """Basic health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'version': app.config.get('VERSION', 'unknown')
    })

@app.route('/health/detailed')
@require_admin
def detailed_health_check():
    """Detailed health check with component status"""
    return jsonify({
        'status': 'healthy',
        'components': {
            'database': check_database_health(),
            'ml_models': check_ml_models_health(),
            'external_apis': check_external_apis_health()
        }
    })
```

---

## 🧪 TESTING ARCHITECTURE

### Testing Strategy

```python
# Test Organization
tests/
├── unit/
│   ├── test_map_providers.py
│   ├── test_image_processing.py
│   ├── test_security.py
│   └── test_configuration.py
├── integration/
│   ├── test_api_endpoints.py
│   ├── test_ml_pipeline.py
│   └── test_user_workflows.py
├── security/
│   ├── test_input_validation.py
│   └── test_configuration_security.py
└── performance/
    ├── test_load_performance.py
    └── test_memory_usage.py
```

### Test Fixtures and Mocks

```python
# ML Model Protection in Tests
@pytest.fixture
def mock_ml_detector():
    """Mock ML detector to avoid loading actual models in tests"""
    mock = Mock(spec=YOLOv5_Detector)
    mock.detect.return_value = generate_test_detections()
    return mock

@pytest.fixture
def test_configuration():
    """Test configuration with safe defaults"""
    return Configuration(
        google_api_key='test_key',
        azure_maps_key='test_azure_key',
        flask_secret_key='test_secret',
        max_tiles=100
    )
```

---

## 📈 PERFORMANCE ARCHITECTURE

### CPU Optimization Strategy

```python
# CPU Performance Optimization
class CPUOptimizedDetector:
    def __init__(self):
        self.device = 'cpu'
        self.batch_size = 4  # Smaller batches for CPU
        self.model = self._load_optimized_model()
    
    def _load_optimized_model(self):
        # Future: torch.quantization integration when approved
        model = load_model(device=self.device)
        model.eval()
        return model
    
    def detect_batch(self, images: List[Image]) -> List[Detection]:
        # Optimized CPU detection with progress tracking
        pass
```

### Memory Management

```python
# Enhanced Memory Management
class ResourceManager:
    def __init__(self):
        self.gpu_semaphore = threading.Semaphore(1)
        self.memory_monitor = MemoryMonitor()
    
    @contextmanager
    def gpu_context(self):
        """Context manager for GPU resource allocation"""
        self.gpu_semaphore.acquire()
        try:
            yield
        finally:
            torch.cuda.empty_cache() if torch.cuda.is_available() else None
            self.gpu_semaphore.release()
```

---

## 🔄 MIGRATION STRATEGY

### Gradual Migration Approach

**Phase 1: Security Foundation**
- Environment variable configuration
- Input validation
- Configuration management
- Error handling infrastructure

**Phase 2: Infrastructure Enhancement**
- Logging system
- Testing framework
- Configuration management
- Health monitoring

**Phase 3: User Experience**
- Simplified setup
- In-app configuration
- Improved error messages
- Mobile responsiveness

**Phase 4: Architecture Optimization**
- Dependency injection
- Performance optimization
- Advanced monitoring
- Documentation completion

### Backward Compatibility

```python
# Compatibility Layer for Gradual Migration
class LegacyCompatibilityLayer:
    """Maintains compatibility during migration"""
    
    def handle_legacy_api_key_loading(self):
        # Support both old and new configuration methods during transition
        if os.path.exists('apikey.txt'):
            warnings.warn("apikey.txt is deprecated, use environment variables")
            return self._load_from_file()
        return self._load_from_environment()
```

---

## 📝 IMPLEMENTATION PRIORITIES

### Component-by-Component Strategy

1. **Flask Application Core** (towerscout.py)
   - Security fixes → UX improvements
   - Error handling → Configuration interface
   - Testing → Documentation

2. **Map Provider System** (ts_maps.py, ts_gmaps.py, ts_bmaps.py)
   - API key security → Provider selection UI
   - Error handling → Usage monitoring
   - Testing → Performance optimization

3. **Image Processing** (ts_imgutil.py)
   - Error handling → Progress tracking
   - Memory optimization → User feedback
   - Testing → Performance monitoring

4. **Session Management** (Flask sessions)
   - Security hardening → Admin interface
   - Cleanup automation → Usage analytics
   - Testing → Monitoring

This design provides a clear roadmap for transforming TowerScout while maintaining its core ML detection capabilities and ensuring security-first development practices.