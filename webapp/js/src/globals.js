// Global Variables Module
// Central location for all global variable declarations
// Extracted from monolithic towerscout.js - Stage 1

(function() {
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
  window.Detection_detections = [];
  window.Detection_detectionsAugmented = 0;
  window.Detection_minConfidence = window.DEFAULT_CONFIDENCE;
  window.Detection_current = null;

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

  // Initialize DOM references safely after DOM is ready
  window.initializeDOMReferences = function() {
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

    console.log('✅ DOM references initialized');
  };

  console.log('✅ Globals module loaded');
})();
