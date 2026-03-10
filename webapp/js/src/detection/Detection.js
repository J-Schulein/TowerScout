// TowerScout - Detection Module
// Detection class and result management
// TASK-038 Stage 4: Extracted from monolithic towerscout.js

(function () {
  'use strict';

  class Detection extends PlaceRect {
    static resetAll() {
      for (let det of Detection_detections) {
        det.select(false);
      }
      // TASK-043 Phase 2: Use state manager for thread-safe clear operation
      providerManager.clearDetections();
      Detection_detectionsAugmented = 0;
      detectionsList.innerHTML = "";

      // FIX NEW-ISSUE-003: Clear Azure Maps detection shapes to prevent duplicates
      if (currentMap && currentMap.detectionDataSource) {
        console.log('🧹 Clearing existing detection shapes from Azure Maps');

        // Get ALL shapes from data source
        const allShapes = currentMap.detectionDataSource.getShapes();

        // Filter to only detection shapes (exclude boundaries)
        const detectionShapes = allShapes.filter(shape => {
          const props = shape.getProperties();
          return props && props.detectionId !== undefined;
        });

        console.log(`🗑️ Removing ${detectionShapes.length} detection shapes from data source`);

        // Remove detection shapes
        if (detectionShapes.length > 0) {
          currentMap.detectionDataSource.remove(detectionShapes);
        }

        // Verify removal
        const remaining = currentMap.detectionDataSource.getShapes().filter(shape => {
          const props = shape.getProperties();
          return props && props.detectionId !== undefined;
        });

        if (remaining.length > 0) {
          console.error(`❌ Failed to clear ${remaining.length} detection shapes!`);
        } else {
          console.log(`✅ All detection shapes cleared from data source`);
        }
      }
    }

    constructor(x1, y1, x2, y2, classname, conf, tile, idInTile, inside, selected, secondary, address, addressConfidence, addressProvider) {
      super(x1, y1, x2, y2, conf === 1.0 ? "blue" : "#FF0000", conf === 1.0 ? "blue" : "#FF0000", 0.15, classname, () => {
        this.highlight(true, true);
      })
      this.conf = conf;
      this.inside = inside;
      this.idInTile = idInTile;
      this.selected = selected;
      this.address = address || "";
      this.addressConfidence = addressConfidence || 0.0;
      this.addressProvider = addressProvider || "none";
      this.maxConf = conf; // maximum confidence across same address towers, only recorded in first
      this.maxSecondary = secondary; // maximum secondary confidence across same address towers, only recorded in first
      this.firstDet = null; // first of block of same address towers
      this.tile = tile; // id of detection tile
      this.secondary = secondary;

      this.id = Detection_detections.length;
      this.originalId = this.id;

      // FIX NEW-ISSUE-003: Update the map feature's detectionId from "pending" to actual numeric ID
      // This must happen BEFORE update() so that show/hide operations can find the feature
      if (this.azureFeature && this.azureFeature.properties) {
        this.azureFeature.properties.detectionId = this.id;
      }
      // TODO: Add similar fix for Google Maps when implementing

      // console.log("Detection #" + this.id + " is " + (this.selected ? "" : "not ") + "selected");
      // TASK-043 Phase 2: Use state manager for thread-safe add operation
      providerManager.addDetection(this);

      // FIX NEW-ISSUE-003: Call update() AFTER setting inside property (PlaceRect no longer calls it)
      this.update();
    }

    static sort() {
      // DEBUG: Log detection order before sorting
      console.log('🔄 Before sort:');
      for (let i = 0; i < Detection_detections.length; i++) {
        console.log(`  [${i}] inside=${Detection_detections[i].inside}, addr="${Detection_detections[i].address.substring(0, 30)}"`);
      }

      // TASK-043 Phase 2: Use state manager for thread-safe sort operation
      providerManager.sortDetections((a, b) => {
        if (a.address < b.address) {
          return -1;
        } else if (a.address > b.address) {
          return 1;
        } else {
          return b.conf - a.conf;
        }
      });

      // DEBUG: Log detection order after sorting
      console.log('🔄 After sort:');
      for (let i = 0; i < Detection_detections.length; i++) {
        console.log(`  [${i}] inside=${Detection_detections[i].inside}, addr="${Detection_detections[i].address.substring(0, 30)}"`);
      }

      // Fix IDs and update map feature AND shape properties
      for (let i = 0; i < Detection_detections.length; i++) {
        let det = Detection_detections[i];
        const oldId = det.id;  // Store old ID before changing
        det.id = i;

        // FIX NEW-ISSUE-004: Update BOTH Feature properties AND Shape properties in data source
        // Azure Maps Shapes have separate property copies that must be synchronized
        if (det.azureFeature && det.azureFeature.properties) {
          det.azureFeature.properties.detectionId = i;
        }

        // FIX NEW-ISSUE-005: Update the Shape in the data source with new detectionId
        if (det.azureShape && typeof det.azureShape.setProperties === 'function') {
          det.azureShape.setProperties({ detectionId: i });
          console.log(`🔄 Updated Shape detectionId from ${oldId} to ${i}`);
        }

        // TODO: Add similar fix for Google Maps when implementing
      }
    }

    static generateList() {
      let currentAddr = "";
      let firstDet = null;
      let boxes = "<ul>";
      let count = 0;
      for (let det of Detection_detections) {
        if (det.address !== currentAddr) {
          if (currentAddr !== "") {
            boxes += "</ul></li>";
          }
          boxes += "<li id='addrli" + det.id + "'>";
          boxes += "<span class='caret' onclick='";
          boxes += "this.parentElement.querySelector(\".nested\").classList.toggle(\"active\"),";
          boxes += "this.classList.toggle(\"caret-down\")';"
          boxes += "'></span>";
          boxes += "<input type='checkbox' id='addrcb" + det.id + "' name='addrcb" + det.id;
          boxes + "' value='";
          boxes += det.id + "' checked style='display:inline;vertical-align:-10%;'"
          boxes += " onclick='Detection_detections[" + det.id + "].selectAddr(this.checked)'>";
          boxes += "<span class='address' id='addrlabel" + det.id + "'";
          boxes += " onclick='Detection.showDetection(" + det.id + ", true)'>"
          boxes += det.address + "</span><br>";
          boxes += "<ul class='nested' id='towerslist" + det.id;
          boxes += "' style='text-indent:-25px; padding-left: 60px;'>";
          currentAddr = det.address;
          firstDet = det;
        }
        boxes += det.generateCheckBox();
        firstDet.maxConf = Math.max(det.conf, firstDet.maxConf); // record max conf in block header
        firstDet.maxSecondary = Math.max(det.secondary, firstDet.maxSecondary || 0)
        det.firstDet = firstDet; // record block header
        det.indexInList = count;
        det.update();
        count++;
      }
      boxes += "</li></ul>";
      detectionsList.innerHTML = boxes;

      // FIX NEW-ISSUE-003: Apply visibility filtering to hide outside detections from list
      // This ensures detections with inside=false don't appear in the right panel
      adjustConfidence();
    }

    generateCheckBox() {
      // Defensive check for tile existence (prevents crash if tiles not loaded)
      let meta = "";
      if (Tile_tiles[this.tile] && Tile_tiles[this.tile].metadata) {
        meta = Tile_tiles[this.tile].metadata;
      }
      // TASK-043 FIX: Show P2 even when it equals 1.0 (was hidden due to < 1.0 condition)
      let p2 = (this.secondary > 0 ? ",&nbsp;P2(" + this.secondary.toFixed(2) + ")" : "")
      let box = "<li><div style='display:block' id='detdiv" + this.id + "'>";
      box += "<input type='checkbox' id='detcb" + this.id + "' name='detcb" + this.id + "'";
      box += " value='" + this.id + "' " + (this.selected ? "checked" : "");
      box += " style='display:inline;vertical-align:-10%;'"
      box += " onclick='Detection_detections[" + this.id + "].select(undefined)'>";
      box += "&nbsp;";
      box += "<span class='address' onclick='Detection.showDetection(" + this.id + ", true)' ";
      box += "id='plabel" + this.id + "'>";
      box += "P(" + this.conf.toFixed(2) + ")" + p2 + (meta !== "" ? ",&nbsp" + meta : "") + "</span></li>";
      box += "</div>";

      this.checkBoxId = 'detdiv' + this.id;
      this.labelId = 'plabel' + this.id;
      return box;
    }

    select(onoff) {
      if (typeof onoff === 'undefined') {
        onoff = !this.selected;
      }
      this.selected = onoff;
      document.getElementById("detcb" + this.id).checked = onoff;
      this.update();
    }

    selectAddr(onoff) {
      if (typeof onoff === 'undefined') {
        onoff = !this.selected;
      }
      for (let det of Detection_detections) {
        if (det.address === this.address) {
          det.selected = onoff;
          document.getElementById("detcb" + det.id).checked = onoff;
          det.update();
        }
      }
    }

    show(onoff) {
      document.getElementById("detdiv" + this.id).style.display = onoff ? "block" : "none";
    }

    isShown() {
      return document.getElementById("detdiv" + this.id).style.display === "block";
    }

    showAddr(onoff) {
      document.getElementById("addrli" + this.id).style.display = onoff ? "block" : "none";
    }

    static showDetection(id, center) {
      Detection_detections[id].highlight(center, false);
    }

    highlight(center, scroll) {
      let firstDet = this.firstDet;

      if (currentAddrElement !== null) {
        currentAddrElement.style.fontWeight = "normal";
        currentAddrElement.style.textDecoration = "";
        currentElement.style.fontWeight = "normal";
        currentElement.style.textDecoration = "";
      }

      // highlight the address
      let element = document.getElementById('addrlabel' + firstDet.id);
      element.style.fontWeight = "bolder";
      element.style.textDecoration = "underline";
      currentAddrElement = element;

      // make sure parent element is open
      element.parentNode.firstChild.classList.add('caret-down');
      // and list displayed
      element.parentNode.lastChild.classList.add('active');

      // highlight the individual detection
      element = document.getElementById(this.labelId);
      if (scroll) {
        currentAddrElement.scrollIntoView({ behavior: 'smooth', block: 'center' });
      }
      element.style.fontWeight = "bolder";
      element.style.textDecoration = "underline";
      currentElement = element;
      document.getElementById("detection").value = this.indexInList;


      if (center) {
        this.centerInMap();
      }

      if (Detection_current !== null) {
        Detection_current.resetHighlight();
      }
      super.highlight("green");
      Detection_current = this;
    }

    resetHighlight() {
      super.highlight(this.color);
    }

    augment(addr) {
      // this.addrSpan.innerText = addr;
      this.address = addr;
      Detection_detectionsAugmented++;
      //console.log("tower " + i + ": " + addr)
    }

    update(newMap) {
      // first, process any map UI change
      super.update(newMap)

      let meetsInside = reviewCheckBox.checked || this.inside;

      // TASK-043 FIX: Use max confidence from either classifier for filtering
      // This preserves both YOLOv5 and EfficientNet detections while allowing slider to work
      let maxConf = Math.max(this.conf, this.secondary || 0);
      let meetsConfidence = maxConf >= Detection_minConfidence;

      // DEBUG: Log visibility decision for diagnosis (first 5 detections only to avoid spam)
      const shouldShow = this.selected && meetsConfidence && meetsInside;
      if (this.id < 5) {
        console.log(`Det ${this.id}: inside=${this.inside}, reviewMode=${reviewCheckBox.checked}, meetsInside=${meetsInside}, shouldShow=${shouldShow}`);
      }

      // IDEMPOTENCY CHECK: Only update if visibility state changed
      if (this._lastVisibilityState !== shouldShow) {
        this.map.updateMapRect(this, shouldShow);
        this._lastVisibilityState = shouldShow;  // Cache state
      } else if (this.id < 5) {
        console.log(`⏭️ Skipping Det ${this.id} - visibility unchanged (${shouldShow})`);
      }
    }

    // navigation for review pane
    static number() {
      let index = document.getElementById("detection").value;
      if (index === "") {
        index = "0";
      } else {
        index = Number(index);
      }
      document.getElementById("detection").value = String(this.navigateTo(index));
    }

    // navigation for review pane
    static prev() {
      let index = document.getElementById("detection").value;
      if (index === "") {
        index = "0";
      } else {
        index = Number(index) - 1;
      }
      document.getElementById("detection").value = String(this.navigateTo(index));
    }

    static next() {
      let index = document.getElementById("detection").value;
      if (index === "") {
        index = "0";
      } else {
        index = Number(index) + 1;
      }
      document.getElementById("detection").value = String(this.navigateTo(index));
    }

    static navigateTo(index) {
      // first, count shown detections
      let count = 0;
      for (let det of Detection_detections) {
        if (det.isShown() && det.selected) {
          count++;
        }
      }
      // limit index to count
      index = ((index % count) + count) % count;

      // now find and center
      let j = 0;
      for (let det of Detection_detections) {
        if (det.isShown() && det.selected) {
          if (j == index) {
            det.highlight(true, true);
            return index;
          }
          j++;
        }
      }
      return index;
    }
  }

  // Expose to window for inline HTML handlers
  window.Detection = Detection;

  console.log('✅ Detection module loaded');

})();
