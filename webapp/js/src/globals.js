// Global Variables Module
// Central location for all global variable declarations
// Extracted from monolithic towerscout.js - Stage 1

(function () {
  'use strict';

  // Geographic constants
  // The location of a spot in central NYC - default map center
  window.nyc = [-74.00820558171071, 40.71083794970947];

  // Default confidence threshold for detection filtering
  window.DEFAULT_CONFIDENCE = 0.15;

  // DOM element references - initialized after DOM ready
  window.input = null;
  window.upload = null;
  window.detectionsList = null;
  window.confSlider = null;
  window.reviewCheckBox = null;

  // Tile management - global tile array
  window.Tile_tiles = [];

  // Detection management - global detection arrays and state
  window.Detection_detectionsAugmented = 0;
  window.Detection_current = null;

  // TASK-043 Phase 2: Detection state deprecation with soft migration
  // Provides backward compatibility while encouraging migration to providerManager
  Object.defineProperty(window, 'Detection_detections', {
    get() {
      // Return direct reference for backward compatibility
      // Mutations will still work but are discouraged
      if (window.providerManager) {
        return window.providerManager.getDetectionsArrayDirect();
      }
      return [];
    },
    set(value) {
      console.warn('⚠️ Direct Detection_detections assignment deprecated. Use providerManager.setDetections() instead.');
      if (window.providerManager) {
        window.providerManager.setDetections(value);
      }
    }
  });

  Object.defineProperty(window, 'Detection_minConfidence', {
    get() {
      if (window.providerManager) {
        return window.providerManager.getMinConfidence();
      }
      return window.DEFAULT_CONFIDENCE;
    },
    set(value) {
      console.warn('⚠️ Direct Detection_minConfidence assignment deprecated. Use providerManager.setMinConfidence() instead.');
      if (window.providerManager) {
        window.providerManager.setMinConfidence(value);
      }
    }
  });

  // Backward compatibility properties for currentProvider and currentMap
  // These provide getters/setters that delegate to providerManager
  Object.defineProperty(window, 'currentProvider', {
    get() {
      return window.providerManager ? window.providerManager.getProvider() : null;
    },
    set(value) {
      console.warn('Direct currentProvider assignment deprecated. Use providerManager.switchProvider()');
      // Allow for backward compatibility but log warning
      if (window.providerManager) {
        window.providerManager.currentProvider = value;
      }
    }
  });

  Object.defineProperty(window, 'currentMap', {
    get() {
      return window.providerManager ? window.providerManager.getMap() : null;
    },
    set(value) {
      console.warn('Direct currentMap assignment deprecated. Use providerManager.switchProvider()');
      // Allow for backward compatibility but log warning
      if (window.providerManager) {
        window.providerManager.currentMap = value;
      }
    }
  });

  // TASK-043 Phase 1: Map instance deprecation with soft migration
  // Provides backward compatibility while encouraging migration to providerManager
  Object.defineProperty(window, 'googleMap', {
    get() {
      return window.providerManager ? window.providerManager.getGoogleMap() : null;
    },
    set(value) {
      console.warn('⚠️ Direct window.googleMap assignment deprecated. Use providerManager.setGoogleMap() instead.');
      // Allow for backward compatibility but log warning
      if (window.providerManager) {
        window.providerManager.setGoogleMap(value);
      }
    }
  });

  Object.defineProperty(window, 'azureMap', {
    get() {
      return window.providerManager ? window.providerManager.getAzureMap() : null;
    },
    set(value) {
      console.warn('⚠️ Direct window.azureMap assignment deprecated. Use providerManager.setAzureMap() instead.');
      // Allow for backward compatibility but log warning
      if (window.providerManager) {
        window.providerManager.setAzureMap(value);
      }
    }
  });

  // Initialize DOM references safely after DOM is ready
  window.initializeDOMReferences = function () {
    console.log('🔧 Initializing DOM references...');

    window.input = document.getElementById("search");
    window.upload = document.getElementById("upload_file");
    window.detectionsList = document.getElementById("checkBoxes");
    window.confSlider = document.getElementById("conf");
    window.reviewCheckBox = document.getElementById("review");

    // Validate critical DOM elements exist
    const criticalElements = [
      { element: window.input, name: 'search input' },
      { element: window.confSlider, name: 'confidence slider' },
      { element: window.reviewCheckBox, name: 'review checkbox' }
    ];

    for (const { element, name } of criticalElements) {
      if (!element) {
        console.error(`❌ Critical DOM element missing: ${name}`);
        throw new Error(`Critical DOM element missing: ${name}. Check HTML template.`);
      }
    }

    // FIX NEW-ISSUE-003: Attach event listeners after validation
    // These were missing after code was moved from towerscout.js to globals.js
    window.confSlider.oninput = adjustConfidence;
    window.reviewCheckBox.onchange = changeReviewMode;

    console.log('✅ DOM references initialized');
  };

  console.log('✅ Globals module loaded');
})();
