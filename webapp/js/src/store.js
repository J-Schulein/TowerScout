// Global State Store Module
// Centralized state management for map instances and application state
// Extracted from monolithic towerscout.js - Stage 1

(function() {
  'use strict';

  // Map provider instances
  window.googleMap = null;
  window.azureMap = null;
  window.currentMap = null;

  // ML engine instances (lazy-loaded)
  window.engines = {};

  // UI state tracking
  window.currentElement = null;           // Currently selected detection marker
  window.currentAddrElement = null;       // Currently selected address list item
  window.isInitializing = true;           // Prevents provider switching during startup

  // Provider manager instance (created in ProviderStateManager.js)
  window.providerManager = null;

  // Manager instances (created in their respective modules)
  window.timerManager = null;
  window.eventManager = null;

  console.log('✅ Store module loaded');
})();
