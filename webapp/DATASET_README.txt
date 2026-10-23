TowerScout dataset export
========================

This archive contains full imagery tiles, selected annotations above the UI
primary/secondary confidence threshold, and contents.txt for TowerScout restore.
Training labels include selected detections outside the Find boundary because
the full tile is included. KML instead uses the current view boundary. Unchecked
or below-threshold detections are omitted intentionally. Review every full image
before training: an image under empty/ is not a verified negative example.

train/images/ contains JPEG tiles; train/labels/ contains YOLO annotations:
  0 center_x center_y width height
Coordinates and dimensions are normalized to the image. Selected manual
annotations are included. Tile dimensions vary by provider/export settings.
contents.txt records tiles, detection/selection data and the metadata flag; it
is not a backup of configuration, model weights or all persistent volumes.

Rights and provenance
---------------------
The application license does not grant rights to provider imagery. Google Maps,
Azure Maps and other imagery remain subject to the applicable provider/account
terms and permissions. Confirm that download, retention, reuse, redistribution
and training are permitted for your source and purpose. An exported archive
alone establishes none of those permissions. See PROVIDER_TERMS.md in the source
or application package. Annotation provenance and applicable rights must be
assessed separately; this README does not automatically license annotations
under AGPL or Creative Commons. Retain source and contributor attribution.

Review/export support: https://github.com/cdcai/TowerScout/issues
Source and current guidance: https://github.com/cdcai/TowerScout
Do not include provider credentials or sensitive imagery in public issues.
