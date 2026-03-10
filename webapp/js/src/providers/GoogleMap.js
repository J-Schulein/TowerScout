// TowerScout - GoogleMap Module
// Google Maps provider implementation
// TASK-038 Stage 3: Extracted from monolithic towerscout.js

(function () {
  'use strict';
  class GoogleMap extends TSMap {
    constructor() {
      super();
      // make the map 
      this.map = new google.maps.Map(document.getElementById("googleMap"), {
        zoom: 19,
        //center: nyc,
        mapTypeId: google.maps.MapTypeId.SATELLITE, // Start with satellite imagery for detection
        fullscreenControl: false,
        streetViewControl: false,
        scaleControl: true,
        mapTypeControl: false, // Disable map type control to prevent switching away from satellite
        maxZoom: 21,
        tilt: 0,
        styles: [
          {
            featureType: 'poi', // Points of interest
            stylers: [{ visibility: 'off' }]
          },
          {
            featureType: 'transit', // Transit stations
            stylers: [{ visibility: 'off' }]
          },
          {
            featureType: 'administrative.locality', // City labels
            elementType: 'labels',
            stylers: [{ visibility: 'off' }]
          },
          {
            featureType: 'road', // Road labels and lines
            elementType: 'labels',
            stylers: [{ visibility: 'off' }]
          }
        ]
      });
      this.boundaries = [];
      this.mapEventListeners = []; // Track map-specific event listeners for cleanup
      this.drawingManager = new google.maps.drawing.DrawingManager({
        drawingMode: null
      });
      this.newShapes = [];

      // TASK-041 Phase 2 Step 2.1: Track created shapes for explicit cleanup
      this.activeShapes = {
        circles: [],      // Circle boundaries created via circle tool
        polygons: [],     // Polygon boundaries drawn by user
        markers: []       // Future: detection result markers
      };

      // Create the search box and link it to the UI element ONLY if Google is the provider
      if (!this.searchBox) {  // Prevent multiple initializations
        this.searchBox = new google.maps.places.SearchBox(input);
      }

      // Bias the SearchBox results towards current map's viewport.
      this.map.addListener("bounds_changed", () => {
        if (currentProvider === 'google' && this.searchBox) {
          this.searchBox.setBounds(this.map.getBounds());
        }
      });

      // Listen for the event fired when the user selects a prediction and retrieve
      // more details for that place.
      this.searchBox.addListener("places_changed", () => {
        // Only handle if Google Maps is the current provider
        if (currentProvider !== 'google') {
          console.log('Ignoring Google Places search - not current provider');
          return;
        }

        let i = 0;
        if (input.value !== '"') {
          this.places = this.searchBox.getPlaces();

          if (this.places.length == 0) {
            console.log("No places found.");
            return;
          }
        }

        let p = input.value;
        if ((p.length === 5 && !isNaN(p)) ||
          (p.length === 7 && p[0] == '"' && p[6] == '"' && !isNaN(p.substring(1, 6))) ||
          (p.startsWith("zipcode "))) {
          // special case: zipcode
          getZipcodePolygon(p);
          return;
        }

        // Google Maps handles its own search
        console.log('Google Maps handling search through Places API');
        this.getBoundsPolygon(input.value, this.places[0]);
      });

      this.drawingManager.setOptions({
        drawingMode: null,
        drawingControl: true,
        drawingControlOptions: {
          position: google.maps.ControlPosition.TOP_CENTER,
          drawingModes: [google.maps.drawing.OverlayType.RECTANGLE,
          google.maps.drawing.OverlayType.POLYGON]
        },
        rectangleOptions: {
          strokeColor: 'green',
          strokeWeight: 2,
          fillColor: 'green',
          fillOpacity: 0.1,
          editable: true,
          draggable: true
        }
      });
      this.drawingManager.setMap(this.map);

      google.maps.event.addListener(this.drawingManager, 'rectanglecomplete', function (rect) {
        googleMap.newShapes.push(rect);
        console.log("new rectangle: " + rect.bounds.toString());
      });

      google.maps.event.addListener(this.drawingManager, 'polygoncomplete', function (poly) {
        googleMap.newShapes.push(poly);
        console.log("new polygon:");
        // let path = poly.getPath();
        // path.forEach((e,i)=>{console.log(" "+e.lng()+","+e.lat())})
      });

      // TASK-041 Phase 1: Initialization milestones marked in initGoogleMap()
      // after constructor completes (styleLoaded, drawingManagerReady)

    }

    retrieveDrawnBoundaries() {
      let polys = [];

      for (let s of this.newShapes) {
        if (typeof s.bounds !== "undefined") {
          // rectangles have bounds
          let ne = s.bounds.getNorthEast();
          let sw = s.bounds.getSouthWest();
          polys.push(new SimpleBoundary([sw.lng(), ne.lat(), ne.lng(), sw.lat()]));
        } else {
          // polygons do not
          let poly = [];
          s.getPath().forEach((e, i) => { poly.push([e.lng(), e.lat()]); });
          polys.push(new PolygonBoundary(poly));
        }
      }
      this.clearShapes()
      return polys;
    }

    hasShapes() {
      return this.newShapes.length !== 0;
    }

    addShapes() {
      let bounds;

      for (let s of this.newShapes) {
        if (typeof s.bounds === "undefined") {
          bounds = new google.maps.LatLngBounds();
          s.getPath().forEach((e) => {
            bounds = bounds.extend(e);
          });
        } else {
          bounds = s.bounds;
        }
        s.setMap(null);

        let x1 = bounds.getSouthWest().lng();
        let y1 = bounds.getNorthEast().lat();
        let x2 = bounds.getNorthEast().lng();
        let y2 = bounds.getSouthWest().lat();

        let tileIds = Tile.getTileIds(x1, y1, x2, y2);
        for (let tileId of tileIds) {
          let tile = Tile_tiles[tileId]
          x1 = Math.max(x1, tile.x1);
          x1 = Math.min(x1, tile.x2);
          x2 = Math.max(x2, tile.x1);
          x2 = Math.min(x2, tile.x2);
          y1 = Math.max(y1, tile.y2);
          y1 = Math.min(y1, tile.y1);
          y2 = Math.max(y2, tile.y2);
          y2 = Math.min(y2, tile.y1);
          let det = new Detection(x1, y1, x2, y2,
            'added', 1.0, tileId, -1, true, true); // id_in_tile parameter
          det.update();
        }
      }
      this.newShapes = [];
      this.drawingManager.setDrawingMode(null);

      Detection.generateList();
      adjustConfidence();
    }

    clearShapes() {
      for (let rect of this.newShapes) {
        rect.setMap(null);
      }
      this.newShapes = [];
      this.drawingManager.setDrawingMode(null);
    }

    clearAll() {
      this.clearShapes();
      // now, also go through Detection_detections and take out the blue ones
      let dets = [];
      for (let det of Detection_detections) {
        if (det.conf !== 1.0) {
          det.id = dets.length;
          dets.push(det);
        }
      }
      Detection_detections = dets;      // FIX NEW-ISSUE-003: generateList() now calls adjustConfidence() to filter outside detections      Detection.generateList();
    }



    getBoundsPolygon(query, place) {
      googleMap.resetBoundaries();
      // Google Maps provider-specific search - only affects Google Maps

      // Handle null/undefined place for Enter-to-search fallback
      const hasPlace = place && place.geometry && place.formatted_address;
      console.log("Querying place outline for: " + query + (hasPlace ? (" (" + place.name + ")") : " (no Place)"));
      if (query[0] === '"' && query.endsWith('"')) {
        // hand this to openstreetmap "as is"
        query = query.substring(1, query.length - 1);
      } else if (hasPlace) {
        // take the google idea of what this is instead
        query = place.formatted_address;
      } // else use the raw query string

      // Fit bounds using place viewport when available, otherwise keep current view
      const viewport = hasPlace ? place.geometry.viewport : googleMap.map.getBounds();
      if (viewport) {
        googleMap.map.fitBounds(viewport);
      }

      $.ajax({
        url: "https://nominatim.openstreetmap.org/search.php",
        data: {
          q: query,
          polygon_geojson: "1",
          format: "json",
        },
        success: function (result) {
          let x = result[0];
          if (typeof x === 'undefined') {
            //googleMap.map.setCenter(place.geometry.location);
            // Fit to place viewport if present; otherwise keep current bounds
            if (hasPlace && place.geometry && place.geometry.viewport) {
              googleMap.map.fitBounds(place.geometry.viewport);
            }
            //googleMap.map.setZoom(19);
            // No Azure Maps dependency - Google provider handles Google Maps only
            return;
          }
          console.log(" Display name: " + x['display_name'] + ": " + x['boundingbox']);
          if (x["geojson"]["type"] == "Polygon" || x["geojson"]["type"] == "MultiPolygon") {
            let bounds = null;
            let ps = x["geojson"]["coordinates"];
            for (let p of ps) {
              if (x["geojson"]["type"] == "MultiPolygon") {
                p = p[0];
              }
              //console.log(" Polygon: " + p);
              //let polyData = parseLatLngArray(p);
              googleMap.addBoundary(new PolygonBoundary(p));
              // Only update Google Maps when Google is the provider
            }
            //console.log(bounds.toUrlValue());
          } else if (x["geojson"]["type"] == "LineString" || x["geojson"]["type"] == "Point") {
            googleMap.map.fitBounds(place.geometry.viewport, 0)
          }
          if (googleMap.boundaries.length > 0) {
            googleMap.showBoundaries();
            // Only show Google Maps boundaries when Google is the provider
          }
        }
      });
    }


    // will always synchronize with the Google map,
    // which should in turn be in sync with the Azure map.
    biasSearchBox() {
      this.searchBox.setBounds(this.map.getBounds());
    }

    getBounds() {
      let bounds = this.map.getBounds();
      let ne = bounds.getNorthEast();
      let sw = bounds.getSouthWest();
      return [sw.lng(), ne.lat(), ne.lng(), sw.lat()];
    }

    fitBounds(x1, y1, x2, y2) {
      let bounds = google.maps.LatLngBounds({
        north: y1,
        south: y2,
        east: x2,
        west: x1
      });
      this.map.fitBounds(bounds);
    }

    setCenter(c) {
      this.map.setCenter({ lat: c[1], lng: c[0] });
      //this.map.setZoom(19);
    }

    getZoom() {
      return this.map.getZoom();
    }

    setZoom(z) {
      this.map.setZoom(z);
    }

    makeMapRect(o, listener) {
      const rectangle = new google.maps.Rectangle({
        strokeColor: o.color,
        strokeOpacity: 1.0,
        strokeWeight: 1,
        fillColor: o.fillColor,
        fillOpacity: o.opacity,
        clickable: true,
        bounds: {
          north: o.y1,
          south: o.y2,
          east: o.x2,
          west: o.x1,
        },
      });
      if (typeof listener !== 'undefined') {
        rectangle.addListener("click", listener);
        rectangle.setOptions({ zIndex: 1000 });
      } else {
        rectangle.setOptions({ zIndex: 0 });
      }
      return rectangle;
    }

    colorMapRect(o, color) {
      o.mapRect.setOptions({ strokeColor: color, fillColor: color, fillOpacity: o.opacity });
    }

    updateMapRect(o, onoff) {
      let r = o.mapRect;
      r.setMap(onoff ? this.map : null)
    }

    resetBoundaries() {
      console.log('🧹 Google Maps: Resetting boundaries...');
      const boundaryCount = this.boundaries.length;

      for (let b of this.boundaries) {
        if (b && b.object) {
          b.object.setMap(null); // Remove from map visually
          b.object = null; // Release reference
        }
      }
      this.boundaries = [];

      // Clear activeShapes tracking
      this.activeShapes.circles = [];
      this.activeShapes.polygons = [];

      console.log(`✅ Google Maps: Removed ${boundaryCount} boundaries from map`);
    }

    clearCircles() {
      console.log(`🔄 Clearing ${this.activeShapes.circles.length} circle(s) from Google Maps...`);

      if (this.activeShapes.circles.length === 0) {
        console.log('✅ No circles to clear');
        return;
      }

      // Step 1: Remove circle polygons from map
      for (let circle of this.activeShapes.circles) {
        if (circle) {
          circle.setMap(null);
        }
      }
      console.log('  - Removed circle polygons from map');

      // Step 2: Filter circles from boundaries array
      const beforeCount = this.boundaries.length;
      this.boundaries = this.boundaries.filter(b => !b.isCircle);
      const removedCount = beforeCount - this.boundaries.length;
      console.log(`  - Removed ${removedCount} circle boundary reference(s)`);

      // Step 3: Clear tracking array
      const clearedCount = this.activeShapes.circles.length;
      this.activeShapes.circles = [];

      console.log(`✅ Cleared ${clearedCount} circle(s)`);
    }

    addBoundary(b) {
      // add to active bounds
      b.index = this.boundaries.length;

      // now make GoogleMap objects and link to them
      let points = b.points.map(p => ({ lng: p[0], lat: p[1] }));
      const poly = new google.maps.Polygon({
        paths: points,
        strokeColor: "#0000FF",
        strokeOpacity: 1,
        strokeWeight: 2,
        fillColor: "#00FF00",
        fillOpacity: 0,
      });
      poly.setMap(googleMap.map);
      b.object = poly;
      b.objectBounds = new google.maps.LatLngBounds();
      for (let p of points) {
        b.objectBounds.extend(p);
      }

      this.boundaries.push(b);

      // TASK-041 Phase 2 Step 2.2: Track circle boundaries for cleanup
      if (b.isCircle) {
        this.activeShapes.circles.push(poly);
        console.log('  - Tracked circle in activeShapes (total:', this.activeShapes.circles.length + ')');
      }


    }

    hasNonCircleBoundaries() {
      return this.boundaries.some(boundary => !boundary.isCircle);
    }

    showBoundaries() {
      // set map bounds to fit union of all active boundaries
      let bounds = new google.maps.LatLngBounds();
      for (let b of this.boundaries) {
        bounds = bounds.union(b.objectBounds);
      }
      this.map.fitBounds(bounds, 0);
    }

    getBoundaryBoundsUrl() {
      // set map bounds to fit union of all active boundaries
      let bounds = new google.maps.LatLngBounds();
      for (let b of this.boundaries) {
        bounds = bounds.union(b.objectBounds);
      }
      return bounds.toUrlValue();
    }

    getBoundariesStr() {
      let result = [];
      for (let b of this.boundaries) {
        result.push(b.toString())
      }
      return "[" + result.join(",") + "]";
    }

    // Memory Management: Cleanup Methods

    cleanupDrawingManager() {
      if (this.drawingManager) {
        console.log('🧹 Cleaning up Google DrawingManager...');

        // Remove all event listeners from drawing manager
        try {
          if (typeof google !== 'undefined' && google.maps && google.maps.event) {
            google.maps.event.clearInstanceListeners(this.drawingManager);
          }
        } catch (e) {
          console.warn('⚠️ Error clearing drawing manager listeners:', e.message);
        }

        // Remove from map
        try {
          this.drawingManager.setMap(null);
        } catch (e) {
          console.warn('⚠️ Error removing drawing manager from map:', e.message);
        }

        this.drawingManager = null;
        console.log('✅ Google DrawingManager cleaned up');
      }
    }

    cleanupMapListeners() {
      if (this.mapEventListeners.length > 0) {
        console.log(`🧹 Cleaning up ${this.mapEventListeners.length} Google map listeners...`);

        for (const listener of this.mapEventListeners) {
          try {
            if (listener.listener && typeof google !== 'undefined' && google.maps && google.maps.event) {
              google.maps.event.removeListener(listener.listener);
            }
          } catch (e) {
            console.warn(`⚠️ Error removing listener ${listener.eventType}:`, e.message);
          }
        }

        this.mapEventListeners = [];
        console.log('✅ Google map listeners cleaned up');
      }
    }

    cleanupSearch() {
      console.log('🧹 Cleaning up Google search infrastructure...');

      // Remove SearchBox listeners
      if (this.searchBox) {
        try {
          if (typeof google !== 'undefined' && google.maps && google.maps.event) {
            google.maps.event.clearInstanceListeners(this.searchBox);
          }
          this.searchBox = null;
        } catch (e) {
          console.warn('⚠️ Error cleaning up search box:', e.message);
        }
      }

      // Clear places cache
      this.places = null;

      console.log('✅ Google search infrastructure cleaned up');
    }

    cleanup() {
      console.log('🧹 Starting Google Maps cleanup...');

      try {
        // 1. Cleanup drawing manager
        this.cleanupDrawingManager();

        // 2. Cleanup map event listeners
        this.cleanupMapListeners();

        // 3. Cleanup search infrastructure
        this.cleanupSearch();

        // 4. Reset boundaries (already correct implementation)
        this.resetBoundaries();

        // 5. Clear drawn shapes
        if (this.newShapes && this.newShapes.length > 0) {
          this.clearShapes();
        }

        console.log('✅ Google Maps cleanup complete');
      } catch (error) {
        console.error('❌ Error during Google Maps cleanup:', error);
        // Don't throw - allow cleanup to complete partially
      }
    }

  }

  // Export to window for global access (IIFE pattern)
  window.GoogleMap = GoogleMap;

  console.log('✅ GoogleMap module loaded');
})();
