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
      Detection_detections.length = 0; // Use mutation pattern from Stage 0
      Detection_detectionsAugmented = 0;
      detectionsList.innerHTML = "";
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
      // console.log("Detection #" + this.id + " is " + (this.selected ? "" : "not ") + "selected");
      Detection_detections.push(this);
    }

    static sort() {
      Detection_detections.sort((a, b) => {
        if (a.address < b.address) {
          return -1;
        } else if (a.address > b.address) {
          return 1;
        } else {
          return b.conf - a.conf;
        }
      });

      // fix ids
      for (let i = 0; i < Detection_detections.length; i++) {
        let det = Detection_detections[i];
        det.id = i;
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
    }

    generateCheckBox() {
      // Defensive check for tile existence (prevents crash if tiles not loaded)
      let meta = "";
      if (Tile_tiles[this.tile] && Tile_tiles[this.tile].metadata) {
        meta = Tile_tiles[this.tile].metadata;
      }
      let p2 = (this.secondary > 0 && this.secondary < 1.0 ? ",&nbsp;P2(" + this.secondary.toFixed(2) + ")" : "")
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

      // FIX: Use secondary classifier threshold for visibility instead of primary confidence
      // Backend selects detections based on secondary >= 0.35, so frontend should too
      let meetsConfidence = this.conf >= Detection_minConfidence || this.secondary >= 0.35;

      // then update by confidence - show if selected and meets either confidence threshold
      this.map.updateMapRect(this, this.selected && meetsConfidence && meetsInside);
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
