# Task Backlog - Future Work Prioritization

**Last Updated**: February 5, 2026  
**Next Planning Session**: February 18, 2026  

---

## 🔥 HIGH PRIORITY - Next Sprint Ready

### **TASK-038: Frontend Code Quality & Refactoring** 🟡
**Status**: NOT_STARTED  
**Type**: B (Technical Debt & Code Quality)  
**Priority**: HIGH  
**Estimated Effort**: 23 hours (spread across sprint)  
**Target Sprint**: Sprint 3 (February 18 - March 4, 2026)

**Objective**: Systematic refactoring of frontend codebase to improve maintainability, reduce technical debt, and establish better architecture

**Context**: Discovered during TASK-037 comprehensive code review. Frontend (towerscout.js) is a 4,759-line monolithic file with duplicate code, inconsistent patterns, and architectural issues that impede future development.

**Requirements**:
- Split monolithic file into logical modules (~12 separate files)
- Consolidate duplicate code (3x getBoundariesStr(), repeated null checks)
- Standardize error handling (remove fatalError(), use TowerScoutErrorHandler)
- Improve provider abstraction (TSMap base class functionality)
- Move magic numbers to CONFIG object
- Add comprehensive input validation
- Improve memory management and cleanup
- Remove debug code from production

**Benefits**:
- Easier to add new map providers (Mapbox, Leaflet)
- Better testability (isolated modules)
- Reduced bundle size (potential jQuery removal)
- Improved code navigation and maintenance
- Foundation for TypeScript migration

**Dependencies**: 
- TASK-037 (User Journey Verification) ✅ PHASE 1 COMPLETE - 8 issues identified and documented
- ISSUE-006, ISSUE-007, ISSUE-008 ✅ FIXED - Critical path unblocked
- ISSUE-001, ISSUE-003, ISSUE-004 deferred to this refactoring task

**Issues to Resolve During Refactoring**:
- ISSUE-001: Provider initialization timing (2-4 hours)
- ISSUE-003: Multiple circles accumulate (1-2 hours)
- ISSUE-004: Clear button non-functional (needs deeper investigation)

**Detailed Plan**: See [FRONTEND-CODE-REVIEW.md](c:\\Users\\bg90\\TowerScout\\.agent_work\\context\\analysis\\FRONTEND-CODE-REVIEW.md)

**Estimated Breakdown**:
- Module splitting: 8 hours
- Error handling standardization: 2 hours  
- Remove jQuery dependency: 4 hours
- Create TowerScoutApp class: 3 hours
- Input validation: 2 hours
- Provider abstraction: 4 hours
- **Total**: 23 hours

---

### **TASK-033: Manual Tower Addition Feature** 🟡
**Status**: NOT_STARTED  
**Type**: B (Feature Development)  
**Priority**: HIGH  
**Estimated Effort**: 3 days  
**Target Sprint**: Sprint 3 (February 18 - March 4, 2026)

**Objective**: Restore ability for users to manually add cooling tower locations using interactive polygon drawing

**Requirements**:
- Interactive polygon drawing on map interface
- Integration with detection results display system
- Session persistence for manual additions
- Export compatibility (KML, CSV, dataset formats)

**Dependencies**: 
- TASK-030 (Address Lookup) ✅ COMPLETED - Address system integration
- TASK-031 (Interactive Highlighting) 🔄 IN CURRENT SPRINT - Selection system integration
- TASK-032 (Enhanced Details Panel) 🔄 IN CURRENT SPRINT - UI integration

**Ready Conditions**: Will be ready after current sprint completes

---

### **TASK-036: Export System Restoration** 🟡
**Status**: NOT_STARTED  
**Type**: B (Feature Development)  
**Priority**: HIGH  
**Estimated Effort**: 2-3 days
**Target Sprint**: Sprint 3 (February 18 - March 4, 2026)

**Note**: Renumbered from TASK-034 to avoid confusion with completed TASK-034 (Client-Side API Key Security)

**Objective**: Restore and enhance data export capabilities for outbreak investigation workflows

**Requirements**:
- Excel/CSV export for epidemiological tracking
- KML export for Google Earth integration
- YOLO format dataset export for ML training
- Batch export with filtering options

**Dependencies**:
- TASK-030 (Address Lookup) ✅ COMPLETED - Address data in exports
- TASK-033 (Manual Addition) - Include manual additions in exports

**Notes**: Critical for outbreak investigation teams

---

## 🟨 MEDIUM PRIORITY - Future Sprints

### **TASK-025: Docker Containerization** 🟡
**Status**: NOT_STARTED  
**Type**: A (Infrastructure)  
**Priority**: MEDIUM  
**Estimated Effort**: 1-2 days
**Target Sprint**: Sprint 3

**Objective**: Create Docker configuration for one-command local deployment

**Requirements**:
- Multi-stage Dockerfile with model weights
- Docker Compose configuration
- Environment variable management
- Platform-specific optimization (AMD64/ARM64)

**Notes**: Enables easier deployment for non-technical users

---

### **TASK-026: CPU Optimization** 🟡
**Status**: NOT_STARTED  
**Type**: C (Performance)  
**Priority**: MEDIUM  
**Estimated Effort**: 2-3 days
**Target Sprint**: Sprint 3-4

**Objective**: Optimize detection pipeline for CPU-only deployment scenarios

**Requirements**:
- torch.quantization implementation for model compression
- Hardware detection and batch size optimization
- Progress indicators for CPU processing
- Memory management for 8GB constraints

**Technical Notes**: Apply model quantization, optimize batch sizes for different hardware profiles

---

### **TASK-027: Enhanced Error Handling** 🟡
**Status**: NOT_STARTED  
**Type**: A (Infrastructure)  
**Priority**: MEDIUM  
**Estimated Effort**: 1-2 days
**Target Sprint**: Sprint 4

**Objective**: Improve user experience with better error messages and recovery

**Requirements**:
- User-friendly error messages for non-technical users
- Graceful degradation for API failures
- Retry mechanisms with exponential backoff
- Error reporting and logging improvements

**Dependencies**: Enhanced logging system

---

### **TASK-028: Mobile Responsiveness** 🟡
**Status**: NOT_STARTED  
**Type**: B (UI/UX)  
**Priority**: MEDIUM  
**Estimated Effort**: 2 days
**Target Sprint**: Sprint 4-5

**Objective**: Improve mobile device compatibility for field investigators

**Requirements**:
- Responsive design for tablet/mobile polygon drawing
- Touch-friendly interface elements
- Optimized map controls for small screens
- Progressive loading for mobile networks

**Notes**: Important for field outbreak investigation teams

---

### **TASK-029: Multi-Provider Fallback** 🟡
**Status**: NOT_STARTED  
**Type**: B (Reliability)  
**Priority**: MEDIUM  
**Estimated Effort**: 2-3 days
**Target Sprint**: Sprint 5

**Objective**: Implement automatic fallback between map providers for reliability

**Requirements**:
- Automatic provider switching on API failures
- Quality comparison and provider selection logic
- Rate limit handling and quota management
- Transparent failover for users

**Dependencies**: Provider abstraction layer ✅ COMPLETED

---

## 🔵 LOW PRIORITY - Backlog

### **Future Enhancement: Advanced Filtering** 🔵
**Type**: B (Feature)  
**Priority**: LOW  
**Estimated Effort**: 3-4 days

**Objective**: Add advanced filtering and search capabilities for large result sets

**Ideas**:
- Confidence threshold sliders
- Geographic filtering (distance, administrative boundaries)
- Historical detection tracking
- Batch operations on filtered results

---

### **Future Enhancement: Performance Dashboard** 🔵
**Type**: A (Monitoring)  
**Priority**: LOW  
**Estimated Effort**: 2 days

**Objective**: Create diagnostic dashboard for troubleshooting and optimization

**Ideas**:
- Processing time metrics
- GPU/CPU utilization monitoring
- API usage tracking
- System health indicators

---

### **Future Enhancement: User Preferences** 🔵
**Type**: B (UX)  
**Priority**: LOW  
**Estimated Effort**: 1-2 days

**Objective**: Add user preference storage and customization

**Ideas**:
- Default map provider selection
- Saved search areas
- Custom confidence thresholds
- Interface layout preferences

---

## 📅 Sprint Planning Guidelines

### **Capacity Management**
- **Sprint Duration**: 2 weeks (10 working days)
- **Estimated Velocity**: 8-12 days per sprint
- **Buffer Time**: 20% for unexpected issues and technical debt

### **Sprint Composition Strategy**
- **Mix**: 70% feature development (Type B), 20% infrastructure (Type A), 10% architecture (Type C)
- **Risk Balance**: Include 1 low-risk task per sprint for momentum
- **Dependencies**: Ensure prerequisite tasks completed before dependent work

### **Priority Adjustment Triggers**
1. **User Feedback**: Outbreak investigation teams report critical workflow gaps
2. **Technical Debt**: Performance issues impact user experience
3. **External Changes**: API changes require urgent adaptation
4. **Security Issues**: Vulnerabilities discovered requiring immediate attention

### **Sprint Planning Process**
1. **Review Completed Work**: Update effort estimates based on actual completion times
2. **Assess Dependencies**: Verify prerequisite tasks are ready
3. **Capacity Planning**: Consider team availability and external commitments  
4. **Risk Assessment**: Identify potential blockers and mitigation strategies
5. **Sprint Goal Setting**: Define clear success criteria for the sprint

### **Backlog Maintenance**
- **Weekly**: Review and update task priorities based on progress and feedback
- **Bi-weekly**: Detailed effort estimation review and dependency validation
- **Monthly**: Strategic priority adjustment and long-term roadmap alignment

## 🎯 Long-Term Objectives

### **Phase 1: Core Features (Sprints 1-2)**
- Complete address lookup and legacy feature restoration
- Establish stable foundation for outbreak investigation workflows

### **Phase 2: Deployment Ready (Sprints 3-4)**
- Docker containerization and CPU optimization
- Enhanced error handling and mobile responsiveness

### **Phase 3: Advanced Features (Sprints 5-6)**
- Multi-provider reliability and advanced filtering
- Performance monitoring and user customization

### **Success Metrics**
- **User Experience**: Outbreak investigation teams can complete workflows without technical assistance
- **Reliability**: 99%+ uptime for critical detection operations
- **Performance**: <30 seconds processing for <100 tiles on consumer hardware
- **Accessibility**: One-command deployment on Windows/Mac/Linux systems