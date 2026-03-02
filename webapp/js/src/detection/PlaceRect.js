// STAGE 4: PlaceRect - Base class for Detection and Tile
// Rectangles on the map (results, tiles, bounding boxes)
(function() {
  'use strict';

  class PlaceRect {

    constructor(x1, y1, x2, y2, color, fillColor, opacity, classname, listener) {
      this.x1 = x1;
      this.y1 = y1;
      this.x2 = x2;
      this.y2 = y2;
      this.color = color;
      this.fillColor = fillColor;
      this.opacity = opacity;
      this.classname = classname;
      this.address = "<unknown address>";
      this.map = currentMap
      this.mapRect = this.map.makeMapRect(this, listener);
      this.update();
      this.listener = listener;
    }

    centerInMap() {
      // this.map.setCenter([(this.x1 + this.x2) / 2, (this.y1 + this.y2) / 2]);
      // currentMap.setZoom(19);
      const targetMap = currentMap || this.map || googleMap;
      if (targetMap && typeof targetMap.setCenter === 'function') {
        targetMap.setCenter([(this.x1 + this.x2) / 2, (this.y1 + this.y2) / 2]);
        if (typeof targetMap.setZoom === 'function') {
          targetMap.setZoom(19);
        }
      }
    }

    getCenter() {
      return [(this.x1 + this.x2) / 2, (this.y1 + this.y2) / 2];
    }

    getCenterUrl() {
      let c = this.getCenter();
      return c[1] + "," + c[0];
    }

    augment(addr) {
      this.addrSpan.innerText = addr;
      this.address = addr;
      //console.log("tower " + i + ": " + addr)
    }

    highlight(color) {
      currentMap.colorMapRect(this, color);
      setTimeout(() => {
        currentMap.colorMapRect(this, this.color);
      }, 5000);
    }

    update(newMap) {
      if (typeof newMap !== 'undefined') {
        this.map.updateMapRect(this, false);
        this.mapRect = newMap.makeMapRect(this, this.listener);
        this.map = newMap;
      }
      this.map.updateMapRect(this, true);
    }
  }

  // Expose PlaceRect to global scope for Detection and Tile classes
  window.PlaceRect = PlaceRect;

  console.log('✅ PlaceRect base class loaded');
})();
