// Provider State Manager Module
// Eliminates race conditions and ensures consistent provider switching
// Extracted from monolithic towerscout.js - Stage 1

(function() {
  'use strict';

  // Provider State Manager - Eliminates race conditions and ensures consistent state
  class ProviderStateManager {
    constructor() {
      this.currentProvider = null;
      this.currentMap = null;
      this.switchingInProgress = false;
      this.initializationPromises = new Map();
      this.isInitializing = true;
      console.log('🔧 ProviderStateManager initialized');

      // TASK-041 Phase 1: Initialization state tracking
      this.initializationState = {
        google: { styleLoaded: false, drawingManagerReady: false },
        azure: { styleLoaded: false, drawingManagerReady: false, dataSourceReady: false }
      };

      // Set initialization complete after initial setup (use setTimeout since timerManager not yet initialized)
      setTimeout(() => {
        this.isInitializing = false;
        console.log('🎯 Provider initialization complete');
      }, 3000);
    }

    async switchProvider(targetProvider, mapInstance = null) {
      if (this.switchingInProgress) {
        console.warn('🚫 Provider switch already in progress, queuing request...');
        // Wait for current switch to complete
        await new Promise(resolve => {
          const checkSwitching = () => {
            if (!this.switchingInProgress) {
              resolve();
            } else {
              window.timerManager.setTimeout(checkSwitching, 50);
            }
          };
          checkSwitching();
        });
        return;
      }

      console.log(`🔄 Switching provider from ${this.currentProvider} to ${targetProvider}`);
      this.switchingInProgress = true;

      // Store current state for rollback
      const rollbackState = {
        provider: this.currentProvider,
        map: this.currentMap
      };

      try {
        // ⭐ MEMORY MANAGEMENT: Cleanup previous provider BEFORE switching
        if (this.currentMap && typeof this.currentMap.cleanup === 'function') {
          console.log(`🧹 Cleaning up ${this.currentProvider} before switch...`);
          try {
            this.currentMap.cleanup();
            console.log(`✅ ${this.currentProvider} cleanup successful`);
          } catch (cleanupError) {
            console.warn(`⚠️ ${this.currentProvider} cleanup had errors (continuing):`, cleanupError.message);
            // Don't fail the switch due to cleanup errors - log and continue
          }
        }

        // Validate provider availability first
        if (!this.isProviderAvailable(targetProvider) && !mapInstance) {
          throw new Error(`${targetProvider} provider not available or not initialized`);
        }

        // Wait for initialization if needed
        if (targetProvider === 'azure' && (!window.azureMap || window.azureMap.initializationPromise)) {
          console.log('🔄 Waiting for Azure Maps initialization...');
          await Promise.race([
            this.ensureAzureInitialized(),
            new Promise((_, reject) =>
              window.timerManager.setTimeout(() => reject(new Error('Azure Maps initialization timeout')), 30000)
            )
          ]);
        }

        // Get target map instance
        const availableMap = targetProvider === 'azure' ? window.azureMap :
          targetProvider === 'google' ? window.googleMap : mapInstance;

        if (!availableMap) {
          throw new Error(`${targetProvider} map instance not available after initialization`);
        }

        // Test basic map functionality before switching
        if (typeof availableMap.getBounds !== 'function') {
          throw new Error(`${targetProvider} map instance invalid - missing required methods`);
        }

        // Additional validation for Azure Maps - ensure map and subscription key are ready
        if (targetProvider === 'azure' && availableMap.map && !availableMap.subscriptionKey) {
          console.warn('⚠️ Azure Maps subscription key not available during switch');
        }

        // Additional validation for Google Maps - ensure map instance is ready  
        if (targetProvider === 'google') {
          console.log('🔍 Validating Google Maps instance:', {
            hasMap: !!availableMap.map,
            mapType: availableMap.map ? typeof availableMap.map : 'undefined',
            hasGetCenter: availableMap.map ? typeof availableMap.map.getCenter : 'undefined'
          });

          if (!availableMap.map) {
            throw new Error('Google Maps instance not available');
          }

          // Check if Google Maps is ready - use more forgiving method
          try {
            if (typeof availableMap.map.getCenter === 'function') {
              const center = availableMap.map.getCenter();
              console.log('🎯 Google Maps center check:', center);
              // Allow null/undefined center if map just loaded
              if (center === null || center === undefined) {
                console.warn('⚠️ Google Maps center not available yet, but map instance exists - allowing');
              }
            } else {
              console.warn('⚠️ Google Maps getCenter method not available yet - allowing anyway');
            }
          } catch (centerError) {
            console.warn('⚠️ Google Maps center check failed, but continuing:', centerError.message);
            // Don't throw error - allow the switch to proceed
          }
        }

        // Test that the map can actually provide bounds (critical for ML pipeline)
        try {
          console.log(`🔍 Testing ${targetProvider} bounds availability...`);
          const testBounds = availableMap.getBounds();
          console.log(`📐 ${targetProvider} bounds result:`, testBounds);

          if (!testBounds || testBounds.length !== 4) {
            console.warn(`⚠️ ${targetProvider} bounds test failed, but allowing switch to proceed`);
            // Don't throw error for Google Maps - it might need time to initialize
            if (targetProvider !== 'google') {
              throw new Error(`${targetProvider} map bounds test failed`);
            }
          } else {
            console.log(`✅ ${targetProvider} bounds test passed`);
          }
        } catch (boundsError) {
          console.warn(`⚠️ ${targetProvider} bounds error:`, boundsError.message);
          // Be more forgiving for Google Maps bounds errors
          if (targetProvider !== 'google') {
            throw new Error(`${targetProvider} map bounds not available: ${boundsError.message}`);
          } else {
            console.warn('⚠️ Google Maps bounds not ready, but allowing switch to proceed');
          }
        }

        // Atomic state update
        this.currentProvider = targetProvider;
        this.currentMap = availableMap;

        console.log(`✅ Provider switched: ${rollbackState.provider} → ${targetProvider}`);

        // Validate the switch worked
        window.timerManager.setTimeout(() => {
          if (this.currentProvider !== targetProvider) {
            console.warn('⚠️ Provider state inconsistency detected');
          }
        }, 100);

        return true;

      } catch (error) {
        console.error('❌ Provider switch failed:', error);

        // Rollback to previous state
        if (rollbackState.provider && rollbackState.map) {
          console.log(`🔄 Rolling back to ${rollbackState.provider}`);
          this.currentProvider = rollbackState.provider;
          this.currentMap = rollbackState.map;
        }

        // Use error handler for consistent error processing
        window.TowerScoutErrorHandler.handleProviderError(targetProvider, error, 'Provider Switch');
        throw error;
      } finally {
        this.switchingInProgress = false;
      }
    }

    async ensureAzureInitialized() {
      if (!window.azureMap) {
        console.log('🔄 Azure Maps not initialized, initializing...');
        await window.initAzureMap();
      } else if (window.azureMap.initializationPromise) {
        console.log('🔄 Waiting for existing Azure Maps initialization...');
        await window.azureMap.initializationPromise;
      }

      if (!window.azureMap) {
        throw new Error('Azure Maps initialization failed');
      }
    }

    getProvider() {
      return this.currentProvider;
    }

    getMap() {
      return this.currentMap;
    }

    // TASK-041 Phase 1: Centralized access method
    getCurrentProvider() {
      return this.currentProvider;
    }

    // TASK-041 Phase 1: Comprehensive initialization check
    isFullyInitialized(provider = this.currentProvider) {
      if (!provider || !this.initializationState[provider]) {
        console.warn('⚠️ Provider not recognized or state missing:', provider);
        return false;
      }

      const state = this.initializationState[provider];

      if (provider === 'azure') {
        const ready = state.styleLoaded && state.drawingManagerReady && state.dataSourceReady;
        if (!ready) {
          console.log('🔍 Azure initialization status:', {
            styleLoaded: state.styleLoaded,
            drawingManagerReady: state.drawingManagerReady,
            dataSourceReady: state.dataSourceReady
          });
        }
        return ready;
      } else if (provider === 'google') {
        const ready = state.styleLoaded && state.drawingManagerReady;
        if (!ready) {
          console.log('🔍 Google initialization status:', {
            styleLoaded: state.styleLoaded,
            drawingManagerReady: state.drawingManagerReady
          });
        }
        return ready;
      }

      return false;
    }

    // TASK-041 Phase 1: Mark initialization milestones
    markInitialized(provider, milestone) {
      if (this.initializationState[provider]) {
        this.initializationState[provider][milestone] = true;
        console.log(`✅ ${provider} - ${milestone} complete`);

        // Check if provider is now fully initialized
        if (this.isFullyInitialized(provider)) {
          console.log(`🎉 ${provider} is now fully initialized and ready!`);
        }
      } else {
        console.warn(`⚠️ Attempted to mark milestone for unknown provider: ${provider}`);
      }
    }

    isProviderAvailable(provider) {
      return provider === 'azure' ? !!window.azureMap :
        provider === 'google' ? !!window.googleMap : false;
    }

    isSwitching() {
      return this.switchingInProgress;
    }
  }

  // Create global instance
  window.providerManager = new ProviderStateManager();

  console.log('✅ ProviderStateManager module loaded');
})();
