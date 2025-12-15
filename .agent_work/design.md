# TowerScout Technical Design Document

## Executive Summary

This document outlines the technical architecture and implementation strategy for transforming TowerScout from a student prototype into a production-ready application. The design follows component-by-component security-first improvements while maintaining ML model integrity.

**Architecture Philosophy**: Incremental improvement with security-first, component-by-component implementation following industry best practices.

**Critical Migration**: Bing Maps → Azure Maps migration with coordinate system validation and Azure Key Vault integration for enterprise deployments.

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

### Target Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    Application Layer                            │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   Web Interface │  │   API Endpoints │  │   Admin Panel   │  │
│  │   (Enhanced)    │  │   (Secured)     │  │   (New)         │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                    Service Layer                               │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   Security      │  │   Configuration │  │   Error         │  │
│  │   Service       │  │   Service       │  │   Handling      │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                    Core Layer (Protected)                      │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   Map Provider  │  │   ML Detection  │  │   Image         │  │
│  │   Abstraction   │  │   Pipeline      │  │   Processing    │  │
│  │   (Enhanced)    │  │   (Unchanged)   │  │   (Enhanced)    │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                                │
┌─────────────────────────────────────────────────────────────────┐
│                    Infrastructure Layer                        │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   Error         │  │   Logging       │  │   Configuration │  │
│  │   Management    │  │   System        │  │   Management    │  │
│  │   (NEW)         │  │   (Enhanced)    │  │   (Enhanced)    │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
│  ┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐  │
│  │   Monitoring    │  │   Retry Logic   │  │   Health        │  │
│  │   & Health      │  │   & Circuit     │  │   Checks        │  │
│  │   (Planned)     │  │   Breaker (NEW) │  │   (Planned)     │  │
│  └─────────────────┘  └─────────────────┘  └─────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🔐 SECURITY ARCHITECTURE

### Authentication & Authorization

```python
# New Security Service Pattern
class SecurityService:
    def __init__(self):
        self.auth_provider = SimpleAuthProvider()
        self.session_manager = SecureSessionManager()
    
    def authenticate_user(self, username: str, password: str) -> AuthResult:
        # Implement secure authentication
        pass
    
    def authorize_request(self, request: Request, required_permission: str) -> bool:
        # Implement authorization checks
        pass
```

### API Key Management

```python
# Environment-based Configuration with Azure Key Vault Support
class ConfigurationService:
    def __init__(self):
        self.google_api_key = os.getenv('GOOGLE_API_KEY')
        self.azure_maps_key = self._get_azure_maps_key()
        
        if not self.google_api_key and not self.azure_maps_key:
            raise ConfigurationError("No map provider API keys configured")
    
    def _get_azure_maps_key(self) -> str:
        # Try Azure Key Vault first, fallback to environment variable
        try:
            from azure.keyvault.secrets import SecretClient
            from azure.identity import DefaultAzureCredential
            
            vault_url = os.getenv('AZURE_KEY_VAULT_URL')
            if vault_url:
                credential = DefaultAzureCredential()
                client = SecretClient(vault_url=vault_url, credential=credential)
                secret = client.get_secret('azure-maps-subscription-key')
                return secret.value
        except Exception:
            pass
        
        # Fallback to environment variable
        return os.getenv('AZURE_MAPS_SUBSCRIPTION_KEY')
```

### Input Validation

```python
# Centralized Validation
class InputValidator:
    @staticmethod
    def validate_polygon(coordinates: List[Tuple[float, float]]) -> ValidationResult:
        # Validate coordinate ranges, format, and polygon validity
        pass
    
    @staticmethod
    def validate_file_upload(file: FileStorage) -> ValidationResult:
        # Validate file type, size, and content
        pass
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
User Request → Input Validation → Authentication → Authorization → Processing → Response
      ↓              ↓                ↓              ↓             ↓           ↓
   Logging       Error Handler    Session Mgmt   Permission    Core Logic   Format
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
│   ├── test_authentication.py
│   ├── test_input_validation.py
│   └── test_authorization.py
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
- Basic authentication
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