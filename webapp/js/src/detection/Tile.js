// TowerScout - Tile Module
// Tile grid system and coordinate mapping
// TASK-038 Stage 4: Extracted from monolithic towerscout.js

(function() {
  'use strict';

class Tile extends PlaceRect {
  static resetAll() {
    for (let tile of Tile_tiles) {
      currentMap.updateMapRect(tile, false);
    }
    Tile_tiles.length = 0; // Use mutation pattern from Stage 0
  }

  constructor(x1, y1, x2, y2, metadata, url) {
    super(x1, y1, x2, y2, "#0000FF", "#0000FF", 0.0, "tile")
    this.metadata = metadata; // for map metadata
    this.url = url

    Tile_tiles.push(this);
  }

  // find the ids for all tiles that the center of this box belongs to
  static getTileIds(x1, y1, x2, y2) {
    let result = [];
    for (let i = 0; i < Tile_tiles.length; i++) {
      let t = Tile_tiles[i]
      // compute center
      let cx = (x1 + x2) / 2;
      let cy = (y1 + y2) / 2;

      // check if center in tile
      if (cx >= t.x1 && cx <= t.x2 && cy <= t.y1 && cy >= t.y2) {
        result.push(i);
      }
    }
    return result;
  }

  // tile navigation for review pane
  static number() {
    let index = document.getElementById("tile").value;
    if (index === "") {
      index = "0";
    } else {
      index = Number(index) % Tile_tiles.length;
    }
    document.getElementById("tile").value = String(index);
    Tile_tiles[index].centerInMap();
  }

  static prev() {
    let index = document.getElementById("tile").value;
    if (index === "") {
      index = "0";
    } else {
      index = (((Number(index) - 1) % Tile_tiles.length) + Tile_tiles.length) % Tile_tiles.length; // don't ask
    }
    document.getElementById("tile").value = String(index);
    Tile_tiles[index].centerInMap();
  }

  static next() {
    let index = document.getElementById("tile").value;
    if (index === "") {
      index = "0";
    } else {
      index = (Number(index) + 1) % Tile_tiles.length;
    }
    document.getElementById("tile").value = String(index);
    Tile_tiles[index].centerInMap();
  }
}

// Expose to window for inline HTML handlers
window.Tile = Tile;

console.log('✅ Tile module loaded');

})();
