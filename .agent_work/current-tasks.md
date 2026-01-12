# Current Tasks - Active Sprint

**Sprint Period**: January 6 - 19, 2026  
**Last Updated**: January 12, 2026  
**Focus**: Legacy Feature Integration & Critical Fixes

## 🔄 IN_PROGRESS

### **TASK-030: Address Lookup for Detections** 🔴
**Status**: 🔄 IN_PROGRESS  
**Type**: B (Feature Development)  
**Priority**: CRITICAL  
**Estimated Effort**: 5-7 days  
**Started**: January 6, 2026  
**Individual Task File**: [TASK-030-address-lookup-implementation.md](TASK-030-address-lookup-implementation.md)

**Objective**: Implement comprehensive address lookup functionality for detected cooling towers to enable outbreak investigation workflow.

**Current Progress**:
- **TASK-030.1**: Provider Management System Improvements ✅ COMPLETED
- **TASK-030.2**: Azure Search Independence Implementation 🔄 IN_PROGRESS (CRITICAL: Map display issues remain)

**Critical Issues**:
- ⚠️ **MAJOR**: Maps still not displaying/operating correctly despite coordinate fixes
- ⚠️ **BLOCKER**: End-to-end functionality not verified due to display problems

**Next Steps**:
1. Debug Map Display: Resolve visualization and interaction issues
2. End-to-End Testing: Validate complete address lookup workflow  
3. Detection Integration: Connect address lookup with cooling tower results

**Dependencies**: Azure Maps migration (TASK-008) ✅ COMPLETED  
**Blocks**: TASK-031, TASK-032 (dependent legacy features)

---

## ⏳ READY TO START

### **TASK-035: Memory Management & Map Object Cleanup** 🟡
**Status**: ⏳ READY  
**Type**: B (Performance)  
**Priority**: HIGH  
**Estimated Effort**: 2 days  

**Objective**: Fix memory leaks in map objects and implement proper cleanup during provider switching

**Issues to Address**:
- Event listeners not removed when switching providers
- Map boundaries and shapes accumulate without disposal
- Drawing managers not properly cleaned up
- Memory usage grows during extended sessions

**Ready Conditions**: Waiting for TASK-030.2 map display issues to be resolved for proper testing environment

**Dependencies**: TASK-024 (Azure Maps Frontend) ✅ COMPLETED, TASK-030.2 resolution pending  

---

## 📋 SPRINT BACKLOG

### **TASK-031: Interactive Highlighting System** 🟡
**Status**: ⏳ NOT_STARTED  
**Type**: B (Feature Development)  
**Priority**: HIGH  
**Estimated Effort**: 1-2 days

**Objective**: Implement bidirectional selection between detection list and map markers

**Blocked By**: TASK-030 (Address Lookup) - requires address display integration  

---

### **TASK-032: Enhanced Details Panel** 🟡
**Status**: ⏳ NOT_STARTED  
**Type**: B (Feature Development)  
**Priority**: HIGH  
**Estimated Effort**: 1-2 days

**Objective**: Create dedicated right-hand panel for displaying detailed detection metadata

**Blocked By**: TASK-030 (Address Lookup), TASK-031 (Interactive Highlighting)

---

## 📊 Sprint Metrics

**Sprint Capacity**: 10-14 days  
**Committed Work**: 5-7 days (TASK-030)  
**Additional Capacity**: 2 days (TASK-035 when ready)  
**Buffer**: 3-5 days for sprint flexibility  

**Critical Path**: TASK-030 → TASK-035 → TASK-031 & TASK-032 (parallel)

**Sprint Goals**:
1. **Complete Address Lookup** (TASK-030) - Foundation for legacy features
2. **Resolve Performance Issues** (TASK-035) - Map stability
3. **Begin UI Enhancements** (TASK-031/032) - If time permits

## 🚨 Sprint Risks

1. **TASK-030.2 Complexity**: Map display debugging may extend beyond estimates
2. **Technical Debt**: Memory management issues may require broader refactoring
3. **Scope Creep**: Legacy features may reveal additional requirements

**Mitigation**: 
- Daily progress check on TASK-030.2
- Timeboxed debugging sessions with clear escalation criteria
- Defer TASK-031/032 to next sprint if TASK-030 extends

## 🎯 Definition of Done

**TASK-030 Complete When**:
- [x] Provider validation accepts both Google and Azure Maps
- [x] Provider switching works without cross-dependencies
- [ ] Address search updates map view correctly for both providers
- [ ] Map displays operate correctly with proper location display
- [ ] Address information can be obtained for detected cooling tower locations
- [ ] End-to-end testing validates outbreak investigation workflow

**Sprint Success Criteria**:
- TASK-030 fully functional and tested
- Memory management issues identified and addressed
- Foundation established for next sprint's UI enhancements