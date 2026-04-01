/**
 * STAGE 5 - UI & Final Integration
 * Module: apiHelpers.js
 * Purpose: Backend API communication and synchronization utilities
 *
 * Functions:
 * - syncUIWithBackendProviders(): Synchronize UI provider selection with backend defaults
 * - validateMapIntegrity(): Validate map state after sizing or initialization changes
 *
 * Dependencies:
 * - providers/ProviderManager.js (providerManager)
 * - window.getBackendProviders (template function, optional)
 *
 * Exposed to window: syncUIWithBackendProviders, validateMapIntegrity
 */

(function () {
  'use strict';

  async function syncUIWithBackendProviders() {
    window.TowerScoutLogger.info('Syncing configured providers...');

    if (window.needsSetup) {
      window.TowerScoutLogger.info('Setup is required before provider sync can continue.');
      return [];
    }

    try {
      if (typeof window.getBackendProviders !== 'function') {
        console.warn('getBackendProviders function not available, using fallback provider detection');

        try {
          const response = await fetch('/getproviders');
          const providers = await response.json();

          if (providers && providers.length > 0) {
            const defaultProvider = providers[0];
            window.TowerScoutLogger.info('Default detection provider:', defaultProvider.id);
            providerManager.currentProvider = defaultProvider.id;

            const googleRadio = document.getElementById('providers-google');
            const azureRadio = document.getElementById('providers-azure');

            if (googleRadio && azureRadio) {
              if (defaultProvider.id === 'google') {
                googleRadio.checked = true;
                azureRadio.checked = false;
              } else if (defaultProvider.id === 'azure') {
                azureRadio.checked = true;
                googleRadio.checked = false;
              }

              window.TowerScoutLogger.debug('UI provider selection synced with backend default (fallback method)');
            }

            return providers;
          }

          console.warn('No providers returned from backend');
          return [];
        } catch (fallbackError) {
          console.error('Fallback provider sync also failed:', fallbackError);
          throw new Error('Unable to sync with backend providers: ' + fallbackError.message);
        }
      }

      const providers = await window.getBackendProviders();

      if (providers && providers.length > 0) {
        const defaultProvider = providers[0];
        window.TowerScoutLogger.info('Default detection provider:', defaultProvider.id);
        providerManager.currentProvider = defaultProvider.id;

        const googleRadio = document.getElementById('providers-google');
        const azureRadio = document.getElementById('providers-azure');

        if (googleRadio && azureRadio) {
          if (defaultProvider.id === 'google') {
            googleRadio.checked = true;
            azureRadio.checked = false;
          } else if (defaultProvider.id === 'azure') {
            azureRadio.checked = true;
            googleRadio.checked = false;
          }

          window.TowerScoutLogger.debug('UI provider selection synced with backend default');
        }

        return providers;
      }

      console.warn('No providers returned from backend');
      return [];
    } catch (error) {
      console.error('Failed to sync with backend providers:', error);
      throw error;
    }
  }

  function validateMapIntegrity() {
    if (window.needsSetup) {
      window.TowerScoutLogger.debug('Setup-required mode active - skipping map integrity validation');
      return true;
    }

    window.TowerScoutLogger.debug('Validating map integrity after sizing changes...');

    if (currentMap && typeof currentMap.getCenter === 'function') {
      const center = currentMap.getCenter();
      window.TowerScoutLogger.debug('Current map center:', center);

      if (!center || !Array.isArray(center) || center.length !== 2) {
        console.error('Invalid map center after resize');
        return false;
      }
    }

    if (currentMap && typeof currentMap.getBounds === 'function') {
      const bounds = currentMap.getBounds();
      window.TowerScoutLogger.debug('Current map bounds:', bounds);
    }

    window.TowerScoutLogger.debug('Map integrity validated');
    return true;
  }

  window.syncUIWithBackendProviders = syncUIWithBackendProviders;
  window.validateMapIntegrity = validateMapIntegrity;

  window.TowerScoutLogger.debug('API Helpers module loaded (backend sync, map validation)');
})();
