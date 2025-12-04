# TASK-021: Frontend Detection Display Fix

## Problem
Cooling towers were being detected correctly by the backend ML pipeline (YOLOv5 + EfficientNet) but were not visually displayed as circles on the frontend map interface.

## Root Cause Analysis

### Backend Logic (CORRECT)
In `webapp/towerscout.py`, line ~470:
```python
object['selected'] = object['secondary'] >= 0.35
```
- Backend uses **secondary classifier (EfficientNet) threshold of 0.35** to determine if a detection should be selected/visible
- This is the correct approach since EfficientNet provides the final classification

### Frontend Logic (BROKEN)
In `webapp/js/towerscout.js`, Detection.update() method:
```javascript
// BROKEN: Only used primary YOLOv5 confidence
this.map.updateMapRect(this, this.selected && this.conf >= Detection_minConfidence && meetsInside);
```

**The Issue:** Frontend was only checking `this.conf >= Detection_minConfidence` (0.15) for visibility, but:
1. Backend selection was based on `secondary >= 0.35`
2. Many valid detections had low YOLOv5 confidence but high EfficientNet confidence
3. This mismatch caused selected detections to be hidden

## Solution Implemented

### 1. Fixed Detection.update() Method
```javascript
// FIXED: Use either primary OR secondary threshold
let meetsConfidence = this.conf >= Detection_minConfidence || this.secondary >= 0.35;
this.map.updateMapRect(this, this.selected && meetsConfidence && meetsInside);
```

### 2. Fixed adjustConfidence() Function
```javascript
// FIXED: Consistent logic with secondary classifier
let meetsConf = det.conf >= Detection_minConfidence || det.secondary >= 0.35;
let meetsAddrConf = det.firstDet.maxConf >= Detection_minConfidence || det.firstDet.maxSecondary >= 0.35;
```

### 3. Added maxSecondary Tracking
```javascript
// NEW: Track maximum secondary confidence for grouped detections
this.maxSecondary = secondary; // in constructor
firstDet.maxSecondary = Math.max(det.secondary, firstDet.maxSecondary || 0); // in generateList()
```

## Files Modified
- `webapp/js/towerscout.js`: Detection.update(), adjustConfidence(), generateList(), constructor

## Testing Requirements
1. Draw polygon over area with cooling towers
2. Verify detection circles appear on map
3. Test confidence slider functionality
4. Confirm detection list shows correctly

## Impact
- **HIGH**: Restores core application functionality
- **SECURITY**: No security implications
- **PERFORMANCE**: Minimal - only affects frontend filtering logic

## Decision Record
**Decision**: Use OR logic for confidence thresholds instead of AND
**Rationale**: Backend selection based on secondary classifier (0.35) should match frontend visibility
**Alternative Considered**: Lower primary confidence threshold - rejected as it would show false positives
**Impact**: Aligns frontend and backend detection logic for consistent user experience