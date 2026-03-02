/**
 * STAGE 5 - UI & Final Integration
 * Module: search.js
 * Purpose: Primary detection workflow and result processing
 * 
 * Functions:
 * - getObjects(estimate): Main detection workflow with boundary validation and tile estimation
 * - processObjects(result, startTime): Result processing with error handling
 * - cancelRequest(): Abort detection request
 * - enableProgress(tiles): Initialize progress indicator
 * - disableProgress(time, actualTiles): Hide progress indicator and update statistics
 * - progressFunction(): Update progress display
 * - setProgress(val): Set progress bar value
 * - fatalError(msg): Display fatal error dialog
 * 
 * Dependencies:
 * - detection/Detection.js (Detection class)
 * - detection/Tile.js (Tile class)
 * - boundaries/SimpleBoundary.js
 * - providers/ProviderManager.js
 * - managers/ErrorHandler.js
 * - CONFIG (global configuration)
 * 
 * Exposed to window: getObjects, processObjects, cancelRequest, fatalError
 */

(function() {
  'use strict';

  // ===== Main Detection Workflow =====

  function getObjects(estimate) {
    //let center = currentMap.getCenterUrl();

    if (!currentMap) {
      const fallbackMap = providerManager.getMap();
      if (fallbackMap) {
        currentMap = fallbackMap;
      }
    }
    if (!currentMap) {
      TowerScoutErrorHandler.showUserNotification(
        'Map is still initializing. Please wait a moment and try again.',
        'warning'
      );
      return;
    }

    if (Detection_detections.length > 0) {
      if (!window.confirm("This will erase current detections. Proceed?")) {
        return;
      }
    }

    let engine = $('input[name=model]:checked', '#engines').val()
    let provider = $('input[name=provider]:checked', '#providers').val()
    console.log('🎯 Detection provider value:', provider, '| Type:', typeof provider);
    console.log('🎯 Provider validation - Azure:', provider === 'azure', '| Google:', provider === 'google');
    // let boundaries = googleMap.getBoundariesStr();
    // if (boundaries === "[]" && radius == "") {
    //   console.log("No boundary selected, instead using viewport: " + googleMap.getBounds())
    //   googleMap.addBoundary(new SimpleBoundary(googleMap.getBounds()));
    // }


    // TASK-041 Phase 2 Step 2.6: Use boundary bounding box instead of viewport bounds
    // This ensures tiles are generated only for the drawn search area, not the entire viewport
    let bounds = currentMap.getBoundaryBoundsUrl();
    console.log('🗺️ Using bounds for tile generation:', bounds);

    if (currentMap && currentMap.boundaries && currentMap.boundaries.length === 0) {
      if (currentMap.hasShapes && currentMap.hasShapes()) {
        drawnBoundary();
      }
    }

    let boundaries = currentMap.getBoundariesStr();

    // Auto-create viewport boundary if no polygons are drawn
    if (boundaries === "[]") {
      console.log("No boundary selected, automatically using current viewport as detection area");
      const bounds = currentMap.getBounds();
      currentMap.addBoundary(new SimpleBoundary(bounds));
      // TASK-041 Phase 1: Sync boundaries to initialized providers only
      if (currentMap === googleMap && azureMap) {
        azureMap.addBoundary(new SimpleBoundary(bounds));
      } else if (currentMap === azureMap && googleMap) {
        googleMap.addBoundary(new SimpleBoundary(bounds));
      }
      boundaries = currentMap.getBoundariesStr();
    }
    let kinds = ["None", "Polygon", "Multiple polygons"]
    if (estimate) {
      console.log("Estimate request in progress");
    } else {
      console.log("Detection request in progress");
    }

    // erase the previous set of towers and tiles
    Detection.resetAll();
    Tile.resetAll();

    // first, play the request, but get an estimate of the number of tiles
    const formData = new FormData();
    formData.append('bounds', bounds);
    formData.append('engine', engine);
    formData.append('provider', provider);
    formData.append('polygons', boundaries);
    formData.append('estimate', "yes");

    fetch("/getobjects", { method: "POST", body: formData, })
      .then(result => {
        if (!result.ok) {
          throw new Error(`HTTP ${result.status}: ${result.statusText}`);
        }

        // Check if result is JSON error instead of tile count
        const contentType = result.headers.get('content-type');
        if (contentType && contentType.includes('application/json')) {
          return result.json().then(errorData => {
            throw new Error(errorData.error || 'Server error');
          });
        }
        return result.text();
      })
      .then(result => {
        // Validate result is a number
        const tileCount = Number(result);
        if (isNaN(tileCount)) {
          throw new Error(`Invalid tile count response: ${result}`);
        }

        if (tileCount === -1) {
          fatalError("Tile limit for this session exceeded. Please close browser to continue.")
          return;
        }
        console.log("Number of tiles: " + tileCount + ", estimated time: "
          + (Math.round(tileCount * secsPerTile * 10) / 10) + " s");
        // let nt = estimateNumTiles(currentMap.getZoom());
        // console.log("  Estimated tiles:" + nt);
        if (estimate) {
          return;
        }

        // actual retrieval process starts here
        let nt = tileCount;
        enableProgress(nt);
        setProgress(0);
        let startTime = performance.now();

        // now, the actual request

        Detection.resetAll();
        formData.delete("estimate");

        const detectionCall = TowerScoutErrorHandler.wrapNetworkCall(
          async () => {
            const response = await fetch("/getobjects", { method: "POST", body: formData });
            if (!response.ok) {
              throw new Error(`Detection failed: HTTP ${response.status} - ${response.statusText}`);
            }
            return await response.json();
          },
          'Cooling Tower Detection'
        );

        detectionCall()
          .then(result => {
            if (!result || !Array.isArray(result)) {
              throw new Error('Invalid detection response format');
            }
            processObjects(result, startTime);
          })
          .catch(error => {
            console.error('❌ Detection pipeline error:', error);
            TowerScoutErrorHandler.handleNetworkError(error, 'Cooling Tower Detection');
            disableProgress(0, 0);
          });
      })
      .catch(error => {
        console.error('❌ Tile estimation error:', error);
        TowerScoutErrorHandler.handleNetworkError(error, 'Tile Estimation');
        let msg = error.message || 'Unknown error occurred';
        if (msg.includes('zipcode')) {
          TowerScoutErrorHandler.showUserNotification(
            'Invalid ZIP code or search area. Please adjust your search boundaries.',
            'error'
          );
        } else {
          TowerScoutErrorHandler.showUserNotification(
            'Detection failed: ' + msg,
            'error'
          );
        }
      });
  }

  function processObjects(result, startTime) {
    if (!Array.isArray(result)) {
      console.error('❌ Invalid result format in processObjects:', result);
      TowerScoutErrorHandler.showUserNotification(
        'Detection failed: Invalid response from server',
        'error'
      );
      disableProgress(0, 0);
      return;
    }

    console.log("Results: " + result.length + " tiles");
    const toRemoveFromEnd = [
      "TILE_TOTAL",
      "OBJECT_TOTAL",
      "API_USAGE_LAST_UPDATE",
      "API_USAGE_ESTIMATE_DAILY",
      "API_USAGE_ESTIMATE_MONTHLY"
    ];

    // Remove trailing metadata elements
    while (result.length > 0 && toRemoveFromEnd.includes(result[result.length - 1][0])) {
      const elem = result.pop();
      if (elem[0] === "API_USAGE_LAST_UPDATE") {
        const usageDiv = document.getElementById("api_usage");
        if (usageDiv) {
          usageDiv.innerHTML = elem[1];
        }
      } else if (elem[0] === "API_USAGE_ESTIMATE_DAILY") {
        const dailyDiv = document.getElementById("api_usage_estimate_daily");
        if (dailyDiv) {
          dailyDiv.innerHTML = elem[1];
        }
      } else if (elem[0] === "API_USAGE_ESTIMATE_MONTHLY") {
        const monthlyDiv = document.getElementById("api_usage_estimate_monthly");
        if (monthlyDiv) {
          monthlyDiv.innerHTML = elem[1];
        }
      } else if (elem[0] === "OBJECT_TOTAL") {
        console.log("Objects detected:" + JSON.parse(elem[1]));
      } else if (elem[0] === "TILE_TOTAL") {
        console.log("After filtering: " + JSON.parse(elem[1]) + " nonempty tiles");
      }
    }

    for (let i = 0; i < result.length; i++) {
      const item = result[i];
      if (!item || !item[0]) continue;

      const detection_kind = item[0];
      const objects_data = item[1];

      if (detection_kind === "OBJECT") {
        Detection.add(Detection.fromJSON(objects_data));
      } else if (detection_kind === "TILE") {
        Tile.add(Tile.fromJSON(objects_data));
      }
    }

    Detection.sortByConfidence();
    Detection.makeList();
    Tile.makeList();
    let time = (performance.now() - startTime) / 1000;
    disableProgress(time, result.length);
    console.log("Request completed in " + time + " s");
  }

  function cancelRequest() {
    disableProgress(0, 0);

    fetch("/abort", { method: "POST" })
      .then(result => {
        console.log("Request cancelled");
      })
      .catch(error => {
        console.error('❌ Cancel request error:', error);
      });
  }

  // ===== Progress Management =====

  function enableProgress(tiles) {
    document.getElementById("progress_div").style.display = "flex";

    // Clear any existing progress timer to prevent memory leaks
    if (progressTimer !== null) {
      clearInterval(progressTimer);
    }
    progressTimer = setInterval(progressFunction, CONFIG.PROGRESS_UPDATE_INTERVAL_MS);
    numTiles = tiles;
    totalSecsEstimated = secsPerTile * numTiles;
    secsElapsed = 0;
  }

  function disableProgress(time, actualTiles) {
    document.getElementById("progress_div").style.display = "none";

    clearInterval(progressTimer);
    if (time !== 0) {
      let secsPerTileLast = time / actualTiles;
      secsPerTile = (secsPerTile * dataPoints + secsPerTileLast) / (dataPoints + 1);
      dataPoints++;
    }
  }

  function progressFunction() {
    secsElapsed += 0.1;
    setProgress(secsElapsed / totalSecsEstimated * 100);
  }

  function setProgress(val) {
    document.getElementById("progress").value = String(val);
  }

  // ===== Error Handling =====

  function fatalError(msg) {
    const div = document.getElementById("fatal_div");
    div.style.display = "flex";
    div.innerHTML = `
      <div style="background: white; padding: 30px; border-radius: 8px; 
                  max-width: 500px; text-align: center; box-shadow: 0 4px 6px rgba(0,0,0,0.3);">
        <p style="color: #d32f2f; font-weight: bold; font-size: 18px; margin-bottom: 15px;">
          ⚠️ Error
        </p>
        <p style="color: #333; margin-bottom: 20px;">${msg}</p>
        <button onclick="this.closest('#fatal_div').style.display='none'; location.reload();" 
                style="background: #1976d2; color: white; border: none; padding: 10px 20px; 
                       border-radius: 4px; cursor: pointer; margin-right: 10px;">
          Refresh Application
        </button>
        <button onclick="this.closest('#fatal_div').style.display='none'" 
                style="background: #757575; color: white; border: none; padding: 10px 20px; 
                       border-radius: 4px; cursor: pointer;">
          Dismiss
        </button>
      </div>
    `;
  }

  // ===== Expose to window for inline HTML handlers =====
  window.getObjects = getObjects;
  window.processObjects = processObjects;
  window.cancelRequest = cancelRequest;
  window.fatalError = fatalError;

  console.log('✅ Search module loaded (detection workflow, progress management)');

})();
