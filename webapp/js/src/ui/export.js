// STAGE 5: Export Functions
// CSV, KML, and dataset download functionality
(function () {
  'use strict';

  /**
   * Download helper - creates temporary anchor and triggers download
   * @param {string} filename - Name of file to download
   * @param {string} data - File content
   */
  function download(filename, data) {
    const blob = new Blob([data], { type: 'text/csv' });
    const elem = window.document.createElement('a');
    elem.href = window.URL.createObjectURL(blob);
    elem.download = filename;
    document.body.appendChild(elem);
    elem.click();
    document.body.removeChild(elem);
  }

  /**
   * Download detection results as dataset ZIP
   * Includes selected detections and manual additions in YOLO format
   */
  function download_dataset() {
    console.log("downloading dataset ...");
    const include = [];
    const additions = [];

    for (let det of Detection_detections) {
      if (det.idInTile !== -1 && det.conf >= Detection_minConfidence && det.selected) {
        include.push({ 'tile': det.tile, 'detection': det.idInTile, 'id': det.originalId });
      }
      if (det.idInTile === -1) {
        const tile = Tile_tiles[det.tile];
        additions.push({
          'tile': det.tile,
          'centerx': (((det.x1 + det.x2) / 2) - tile.x1) / (tile.x2 - tile.x1),
          'centery': (((det.y1 + det.y2) / 2) - tile.y1) / (tile.y2 - tile.y1),
          'w': (det.x2 - det.x1) / (tile.x2 - tile.x1),
          'h': (det.y1 - det.y2) / (tile.y1 - tile.y2)
        });
      }
    }

    const formData = new FormData();
    formData.append("include", JSON.stringify(include));
    formData.append("additions", JSON.stringify(additions));

    fetch("getdataset", { method: 'POST', body: formData })
      .then(response => response.blob())
      .then(blob => {
        const elem = window.document.createElement('a');
        elem.href = window.URL.createObjectURL(blob);
        elem.download = "dataset.zip";
        document.body.appendChild(elem);
        elem.click();
        document.body.removeChild(elem);
      })
      .catch(error => {
        console.log("error in download: " + error);
      });
  }

  /**
   * Download detection results as CSV
   * Format: id, selected, inside_boundary, meets_threshold, lat, lng, distance, address, confidence
   */
  function download_csv() {
    let text = "id,selected,inside_boundary,meets threshold,latitude (deg),longitude (deg),distance from center (m),address,confidence\n";

    for (let i = 0; i < Detection_detections.length; i++) {
      const det = Detection_detections[i];
      text += [
        i,
        det['selected'],
        reviewCheckBox.checked || det.inside,
        det['conf'] >= confSlider.value / 100,
        det.getCenter()[1].toFixed(8),
        det.getCenter()[0].toFixed(8),
        getDistance(det.getCenter(), currentMap.getCenter()).toFixed(1),
        ('"' + det['address'] + '"'),
        det['conf'].toFixed(2)
      ].join(",") + "\n";
    }

    download("detections.csv", text);
  }

  /**
   * Download detection results as KML for Google Earth
   * Includes styled markers and detection metadata
   */
  function download_kml() {
    let text = '<?xml version="1.0" encoding="UTF-8"?>\n';
    text += '<kml xmlns="http://www.opengis.net/kml/2.2">\n';
    text += "  <Document>\n";

    // Add KML styles
    text += "<Style id='icon-1736-0F9D58-normal'><IconStyle><color>ffffa0a0</color><scale>1</scale>";
    text += "<Icon><href>https://maps.google.com/mapfiles/kml/pal4/icon35.png</href></Icon>";
    text += "</IconStyle><LabelStyle><scale>0</scale></LabelStyle></Style>\n";

    text += "<Style id='icon-1736-0F9D58-highlight'><IconStyle><color>ffa0a0ff</color><scale>1</scale>";
    text += "<Icon><href>https://maps.google.com/mapfiles/kml/pal4/icon35.png</href></Icon>";
    text += "</IconStyle><LabelStyle><scale>1</scale></LabelStyle></Style>\n";

    text += "<StyleMap id='icon-1736-0F9D58'><Pair><key>normal</key><styleUrl>";
    text += "#icon-1736-0F9D58-normal</styleUrl></Pair><Pair><key>highlight</key>";
    text += "<styleUrl>#icon-1736-0F9D58-highlight</styleUrl></Pair></StyleMap>\n\n";

    text += "<Style id='icon-1736-0F9D58-nodesc-normal'><IconStyle><color>ffffa0a0</color><scale>1</scale>";
    text += "<Icon><href>http://maps.google.com/mapfiles/kml/pal4/icon35.png</href></Icon>";
    text += "</IconStyle><LabelStyle><scale>0</scale></LabelStyle>";
    text += "<BalloonStyle><text><![CDATA[<h3>$[name]</h3>]]></text></BalloonStyle></Style>\n";

    text += "<Style id='icon-1736-0F9D58-nodesc-highlight'><IconStyle><color>ffa0a0ff</color><scale>1</scale>";
    text += "<Icon><href>http://maps.google.com/mapfiles/kml/pal4/icon35.png</href></Icon>";
    text += "</IconStyle><LabelStyle><scale>1</scale></LabelStyle>";
    text += "<BalloonStyle><text><![CDATA[<h3>$[name]</h3>]]></text></BalloonStyle></Style>\n";

    text += "<StyleMap id='icon-1736-0F9D58-nodesc'><Pair><key>normal</key><styleUrl>";
    text += "#icon-1736-0F9D58-nodesc-normal</styleUrl></Pair><Pair><key>highlight</key>";
    text += "<styleUrl>#icon-1736-0F9D58-nodesc-highlight</styleUrl></Pair></StyleMap>\n\n";

    // Add placemarks for each detection
    for (let det of Detection_detections) {
      const inside = reviewCheckBox.checked || det.inside;
      if (det.conf >= Detection_minConfidence && det.selected && inside) {
        text += "    <Placemark>\n";
        text += '      <name>' + det.address + '</name>\n';

        const tileMeta = (Tile_tiles[det.tile] && Tile_tiles[det.tile].metadata) ? Tile_tiles[det.tile].metadata : '';
        text += '      <description>P(' + det.conf.toFixed(2) + ') at ' + det.address + ' ' + tileMeta + '</description>\n';
        text += "      <styleUrl>#icon-1736-0F9D58</styleUrl>\n";
        text += '      <Point>\n';
        text += '        <altitudeMode>relativeToGround</altitudeMode>\n';
        text += '        <extrude>1</extrude>\n';
        text += '        <coordinates>' + det.getCenter()[0] + ',' + det.getCenter()[1] + ',300</coordinates>\n';
        text += '      </Point>\n';
        text += "    </Placemark>\n";
      }
    }

    text += "  </Document>\n";
    text += '</kml>\n';
    download("detections.kml", text);
  }

  // Expose functions to window for inline HTML handlers
  window.download_dataset = download_dataset;
  window.download_csv = download_csv;
  window.download_kml = download_kml;

  console.log('✅ Export functions loaded');
})();
