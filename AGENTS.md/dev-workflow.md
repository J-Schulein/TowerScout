# TowerScout Development Workflow

## Development Workflows

**Current Local Development Setup:**
```bash
# Standard local development approach
cd webapp
python towerscout.py dev
```

**Local Deployment Docker Strategy:**
```dockerfile
# Use specific Python version, security-focused base
FROM python:3.12-slim

# Don't run as root
RUN useradd --create-home --shell /bin/bash app
USER app

# Environment-based configuration
ENV FLASK_ENV=development
ENV GOOGLE_API_KEY=""
ENV AZURE_MAPS_KEY=""
```

**Dependencies Critical Notes:**
- `fiona==1.9.6` pinned due to GDAL compatibility issues
- `torch` without CUDA in requirements.txt (CPU fallback missing)
- Core: `torch`, `torchvision`, `flask`, `waitress`
- CV: `opencv-python`, `Pillow`, `efficientnet_pytorch`, `rasterio`
- GIS: `geopandas`, `Shapely`, `fiona==1.9.6`
- Async: `aiohttp`, `aiofiles`

**Asset Management:**
- YOLOv5 weights: Download `newest.pt` from Google Drive to `model_params/yolov5/`
- EfficientNet weights: Download from Google Drive to `model_params/EN/`
- US Shapefile: Census TIGER data to `data/` directory
- **Docker Strategy:** Embed models in container (~1.2GB) for one-command local deployment

**Performance Optimization:**
- Hardware detection for GPU/CPU/Apple Silicon MPS capabilities
- Platform-specific batch size optimization (AMD64: 8-16, ARM64: 4-8, CPU: 4)
- Memory monitoring and management for 8GB RAM constraints
- Implement proper async patterns for I/O operations (currently mixed sync/async)
- Monitor GPU memory with CUDA device properties
- Use vectorized numpy operations for imagery processing

**Debugging Detection Issues:**
- Check `session['tiles']` for tile count limits
- Use tile debugging mode (returns tile boundaries as pseudo-results)
- Check polygon intersection with `ts_imgutil.tileIntersectsPolygons()`
- Test cross-provider imagery compatibility (Google vs Azure)
- **Hardware Testing:** Hardware compatibility testing (GPU/CPU/MPS detection)
- **Configuration Testing:** API key validation and network connectivity testing

**Deployment Strategy:**
- **Current Strategy:** Docker containerization for local deployment
- Base: Python 3.12-slim, optional NVIDIA CUDA runtime
- Volume mounts for models, data, and configuration
- Environment-based configuration for API keys

## Version Control Integration

- Create feature branches for Type B/C requests
- Use descriptive commit messages following conventional commits format
- Tag decision points and milestones for complex changes

## Git Workflow Integration (TowerScout-Optimized)

### Branch Strategy - Solo Development with Paper Trail

**Primary Workflow:**
```bash
main -> feature/improvement branch -> main (via PR)
```

**Branch Naming Convention:**
- `feature/ui-improvement-<description>` - UI/UX enhancements
- `fix/security-<issue>` - Security fixes (Type C - critical)
- `fix/bug-<description>` - Bug fixes (Type A)
- `docs/update-<section>` - Documentation updates
- `refactor/code-quality-<component>` - Code quality improvements

### Commit Strategy - Frequent and Descriptive

**Commit Message Format:**
```
<type>(<scope>): <description>

[optional body explaining what and why]

[optional footer with issue references]
```

**Types:**
- `feat:` - New UI/UX features
- `fix:` - Bug fixes
- `security:` - Security improvements
- `refactor:` - Code improvements without functionality change
- `docs:` - Documentation updates
- `style:` - CSS/UI styling changes
- `test:` - Adding tests

**Examples:**
```bash
feat(ui): add progress indicator for detection processing
fix(security): migrate API keys from plain text to environment variables
style(mobile): improve responsive design for polygon drawing
refactor(maps): abstract map provider interface for better testability
```

### ML Model Protection Strategy

**Protected Paths** (avoid changes):
- `model_params/` - Pre-trained model weights
- `Model/` - Training notebooks and evaluation scripts
- Core detection logic in `ts_yolov5.py` and `ts_en.py`

**Safe Improvement Areas:**
- `webapp/towerscout.py` - Flask routes and session management
- `templates/` - HTML templates and user interface
- `css/`, `js/` - Frontend styling and interactions
- `ts_maps.py`, `ts_gmaps.py`, `ts_azure_maps.py` - Map provider interfaces
- Configuration and deployment scripts

### Commit Frequency Guidelines

**High Frequency (Every Change):**
- Each UI component modification
- Each security fix iteration
- Configuration file updates
- Documentation improvements

**Medium Frequency (Per Feature):**
- Complete user workflow improvements
- API endpoint modifications
- Error handling enhancements

**Checkpoint Commits:**
- Before starting risky refactoring
- After successful validation phases
- At decision points documented in decision records

### Paper Trail Documentation

**Required for Each PR:**
1. **Executive Summary** - What changed and why
2. **Impact Assessment** - User experience improvements
3. **ML Model Safety** - Confirmation no detection logic modified
4. **Testing Evidence** - Screenshots, validation results
5. **Decision Records** - Links to architectural choices made

**Automated Paper Trail:**
- Commit messages provide granular change history
- PR descriptions provide feature-level summaries
- Decision records provide architectural rationale
- Issue references provide requirement traceability

## Coding Guidelines for Improvements

**Developer Guidelines:**
- Follow coding standards and best practices
- Ensure code readability and maintainability
- Conduct thorough code reviews
- Use meaningful variable and function names. Ensure consistency and clarity.
- Maintain comprehensive inline documentation for complex logic.
- Ensure proper authentication and authorization for all endpoints.
- Before creating new classes and functions, evaluate existing ones for reuse.
- Always be skeptical of whether your developed solutions have been implemented properly and securely.
- Continuously review and refactor code to improve security and performance.
- Pay close attention to potential instances of orphaned code, unused dependencies, and infinite recursion issues.
- Ensure solutions comprehensively address all identified requirements and edge cases without creating additional complexity or unforeseen consequences.

**Quality Standards:**
- Add logging for all operations (use Python `logging` module)
- Implement proper exception handling with specific exception types
- Write testable code with dependency injection
- Follow PEP 8 style guidelines

**TowerScout-Specific:**
- Preserve CV model accuracy when optimizing
- Maintain coordinate system precision for geographic accuracy
- Test cross-platform compatibility (Windows/Linux/macOS) for local deployment
- Ensure CPU fallback works without GPU hardware (critical for diverse user hardware)
- Implement user-friendly error messages for non-technical users
- Support hardware detection and platform-specific optimization

**Performance Considerations:**
- Monitor GPU memory usage and implement proper cleanup
- Use vectorized operations for image processing
- Implement proper async patterns for I/O operations
- Cache model weights to avoid repeated loading
- **Hardware Detection:** Platform-specific batch sizing and optimization
- **Memory Management:** Constraint handling for 8GB systems
- **CPU Processing:** Progress indicators and optimization for CPU-only processing
