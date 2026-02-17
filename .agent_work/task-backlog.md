# Task Backlog - Future Work Prioritization

**Last Updated**: February 17, 2026  
**Sprint 02 Period**: February 18 - March 4, 2026  
**Next Sprint Planning**: March 4, 2026  

---

## 🔥 HIGH PRIORITY - Sprint 03 Ready

### **TASK-039: Google Maps API Upgrade (ISSUE-005)** 🔴
**Status**: NOT_STARTED  
**Type**: B (Technical Debt & Code Quality)  
**Priority**: HIGH  
**Estimated Effort**: 23 hours (spread across sprint)  
**Target Sprint**: Sprint 02 (February 18 - March 4, 2026) ✅ MOVED TO ACTIVE
**Status**: IN_PROGRESS - MOVED TO current-tasks.md

---

### **TASK-039: Google Maps API Upgrade (ISSUE-005)** 🔴
**Status**: NOT_STARTED  
**Type**: C (Architecture - API Migration)  
**Priority**: CRITICAL  
**Estimated Effort**: 8-20 hours  
**Target Sprint**: Sprint 3-4 (Must complete by April 2026)  
**Hard Deadline**: April 2026 (Breaking change in May 2026)

**Objective**: Migrate from deprecated Google Maps APIs before they are removed in May 2026

**Context**: 
- Discovery Date: February 5, 2026 during TASK-037 user journey testing
- Google Maps Drawing Library deprecated August 2025, removal scheduled May 2026
- SearchBox API deprecated March 2025 for new customers
- Application currently using retired version (v3.55.1)

**Technical Details**:
- **Current State**: Using deprecated Drawing Library for polygon/circle tools
- **Impact**: Complete failure of Google Maps provider after May 2026
- **Affected Components**: Circle tool, polygon tool, all interactive drawing features
- **Console Warnings**:
  ```
  ⚠️ Drawing library functionality in the Maps JavaScript API is deprecated.
     Removal scheduled for May 2026.
  ⚠️ google.maps.places.SearchBox not available to new customers.
  ⚠️ RetiredVersion warning - using v3.55.1
  ```

**Requirements**:
- Upgrade to latest Google Maps JavaScript API version
- Replace deprecated Drawing Library with new drawing tools API
- Migrate SearchBox to Places Autocomplete API  
- Maintain feature parity with current polygon/circle drawing capabilities
- Ensure backward compatibility with existing boundary data structures
- Test all Google Maps provider functionality after migration

**Migration Strategy**:
1. **API Version Upgrade** (2-3 hours):
   - Update Google Maps script loading to latest version
   - Review and update any breaking changes in core API
   - Update initialization code for new API patterns

2. **Drawing Tools Migration** (4-8 hours):
   - Research new Google Maps drawing tools API
   - Replace DrawingManager with new drawing implementation
   - Migrate polygon creation functionality
   - Migrate circle creation functionality
   - Ensure drawing event handlers work correctly

3. **Places API Migration** (2-4 hours):
   - Replace SearchBox with Places Autocomplete
   - Update address search integration
   - Verify geocoding functionality unchanged

4. **Testing & Validation** (2-5 hours):
   - Cross-browser testing (Chrome, Edge, Firefox, Safari)
   - Verify all drawing tools work as expected
   - Test provider switching (Google ↔ Azure)
   - Validate boundary data compatibility
   - Performance testing for API call efficiency

**Risk Assessment**:
- **HIGH**: Complete provider failure if not addressed before May 2026
- **MEDIUM**: Potential breaking changes in new API requiring code restructuring
- **LOW**: User workflow disruption (can be mitigated with thorough testing)

**Dependencies**: 
- TASK-041 (Deep Dive Priority 2) ✅ COMPLETE - Clean architecture foundation
- TASK-037 (User Journey Verification) - Re-test after migration

**Success Criteria**:
- [ ] No deprecation warnings in browser console
- [ ] All drawing tools functional on Google Maps provider
- [ ] Address search working with new Places API
- [ ] Provider switching works seamlessly
- [ ] Boundary data compatibility maintained
- [ ] Performance equivalent or better than current implementation

**Notes**: 
- **DO NOT DEFER BEYOND APRIL 2026** - This is a hard deadline
- Consider implementing this in Sprint 3 to avoid last-minute rush
- May want to implement provider fallback (Azure Maps) during transition period
- Document migration process for future API updates

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
- TASK-031 (Interactive Highlighting) ✅ COMPLETED (Sprint 01) - Selection system integration
- TASK-032 (Enhanced Details Panel) ✅ COMPLETED (Sprint 01) - UI integration

**Ready Conditions**: Dependencies all met, ready for Sprint 03

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