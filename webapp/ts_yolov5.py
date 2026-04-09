#
# TowerScout
# A tool for identifying cooling towers from satellite and aerial imagery
#
# TowerScout Team:
# Karen Wong, Gunnar Mein, Thaddeus Segura, Jia Lu
#
# Licensed under CC-BY-NC-SA-4.0
# (see LICENSE.TXT in the root of the repository for details)
#

# YOLOv5 detector class

import math
import os
import shutil
import threading
from pathlib import Path

import torch
from PIL import Image

from ts_imgutil import crop
from ts_errors import ModelLoadError, ProcessingError, ResourceError
from ts_logging import get_ml_logger

logger = get_ml_logger()

YOLOV5_HUB_REPO = 'ultralytics/yolov5'
YOLOV5_HUB_CACHE_PREFIX = 'ultralytics_yolov5_'
YOLOV5_STALE_IMPORT_SIGNATURE = 'import pkg_resources as pkg'
YOLOV5_HUB_ARCHIVES = ('master.zip', 'main.zip')


def _is_pkg_resources_missing_error(error):
    """Detect the stale-cache failure mode caused by old YOLOv5 Hub snapshots."""
    current = error
    seen = set()

    while current is not None and id(current) not in seen:
        if isinstance(current, ModuleNotFoundError) and getattr(current, 'name', None) == 'pkg_resources':
            return True

        if "No module named 'pkg_resources'" in str(current):
            return True

        seen.add(id(current))
        current = current.__cause__ or current.__context__

    return False


def _find_stale_yolov5_hub_repos():
    """Return cached YOLOv5 Hub repos that still import pkg_resources."""
    hub_dir = Path(torch.hub.get_dir())
    stale_repos = []

    if not hub_dir.exists():
        return hub_dir, stale_repos

    for repo_dir in hub_dir.glob(f'{YOLOV5_HUB_CACHE_PREFIX}*'):
        if not repo_dir.is_dir():
            continue

        general_py = repo_dir / 'utils' / 'general.py'
        try:
            if general_py.exists() and YOLOV5_STALE_IMPORT_SIGNATURE in general_py.read_text(encoding='utf-8', errors='ignore'):
                stale_repos.append(repo_dir)
        except OSError:
            continue

    return hub_dir, stale_repos


def _clear_stale_yolov5_hub_repos(hub_dir, stale_repos):
    """Remove stale cached YOLOv5 Hub repos so torch.hub can fetch a fresh snapshot."""
    for repo_dir in stale_repos:
        shutil.rmtree(repo_dir)

    for archive_name in YOLOV5_HUB_ARCHIVES:
        archive_path = hub_dir / archive_name
        if archive_path.exists():
            archive_path.unlink()


def _load_model_with_cache_recovery(filename):
    """Retry once if a stale cached YOLOv5 Hub snapshot still depends on pkg_resources."""
    try:
        return torch.hub.load(YOLOV5_HUB_REPO, 'custom', path=filename)
    except Exception as first_error:
        if not _is_pkg_resources_missing_error(first_error):
            raise

        hub_dir, stale_repos = _find_stale_yolov5_hub_repos()
        if not stale_repos:
            raise

        stale_repo_list = ', '.join(str(path) for path in stale_repos)
        logger.warning(
            "Detected stale cached YOLOv5 Torch Hub repo requiring pkg_resources. "
            "Clearing cache and retrying fresh load: %s",
            stale_repo_list
        )

        try:
            _clear_stale_yolov5_hub_repos(hub_dir, stale_repos)
        except OSError as clear_error:
            raise RuntimeError(
                "Detected stale cached YOLOv5 Torch Hub repo that requires pkg_resources, "
                f"but failed to clear it: {clear_error}"
            ) from clear_error

        try:
            return torch.hub.load(YOLOV5_HUB_REPO, 'custom', path=filename, force_reload=True)
        except Exception as retry_error:
            raise RuntimeError(
                "Detected stale cached YOLOv5 Torch Hub repo that required pkg_resources. "
                f"Cleared stale cache under {hub_dir} and retried a fresh download, but reload failed: {retry_error}"
            ) from retry_error


class YOLOv5_Detector:
    def __init__(self, filename):
        try:
            logger.info(f"Initializing YOLOv5 detector with model: {filename}")
            
            # Validate model file exists
            if not os.path.exists(filename):
                raise ModelLoadError(
                    f"YOLOv5 model file not found: {filename}",
                    model_name="YOLOv5",
                    model_path=filename
                )
            
            # Model loading with error handling
            try:
                self.model = _load_model_with_cache_recovery(filename)
                logger.info("YOLOv5 model loaded successfully")
            except Exception as e:
                raise ModelLoadError(
                    f"Failed to load YOLOv5 model: {str(e)}",
                    model_name="YOLOv5",
                    model_path=filename,
                    cause=e
                )
            
            # GPU/CPU configuration with error handling
            if torch.cuda.is_available():
                try:
                    self.model.cuda()
                    t = torch.cuda.get_device_properties(0).total_memory
                    r = torch.cuda.memory_reserved(0)
                    a = torch.cuda.memory_allocated(0)
                    f = r-a  # free inside reserved
                    logger.info(f"CUDA enabled - Free GPU memory: {f:,} bytes")
                    self.batch_size = 8  # For our Tesla K8, this means 8 batches can run in parallel
                except Exception as e:
                    logger.warning(f"CUDA setup failed, falling back to CPU: {e}")
                    self.batch_size = torch.get_num_threads()  # tuned to threads
            else:
                logger.info("CUDA not available, using CPU")
                self.batch_size = torch.get_num_threads()  # tuned to threads
            
            # add a semaphore so we don't run out of GPU memory between multiple clients
            self.semaphore = threading.Semaphore(8)
            
        except Exception as e:
            if isinstance(e, ModelLoadError):
                raise
            else:
                raise ModelLoadError(
                    f"Unexpected error during YOLOv5 initialization: {str(e)}",
                    model_name="YOLOv5",
                    model_path=filename,
                    cause=e
                )

    def detect(
        self,
        tiles,
        events,
        id,
        crop_tiles=False,
        secondary=None,
        perf_metrics=None,
        progress_callback=None,
    ):
        try:
            logger.info(f"Starting YOLOv5 detection on {len(tiles)} tiles")
            
            # Track memory before detection starts
            if perf_metrics:
                perf_metrics.update_memory_usage()
            
            # Inference in batches
            tile_count = len(tiles)
            chunks = math.ceil(tile_count/self.batch_size)
            results = []
            count = 0

            for i in range(0, tile_count, self.batch_size):
                try:
                    # make a batch of image urls
                    tile_batch = tiles[i:i+self.batch_size]
                    logger.debug(f"Processing batch {i//self.batch_size + 1}/{chunks}: {len(tile_batch)} tiles")
                    
                    # Load images with error handling
                    img_batch = []
                    for tile in tile_batch:
                        try:
                            img_batch.append(Image.open(tile['filename']))
                        except Exception as e:
                            logger.error(f"Failed to load image {tile['filename']}: {e}")
                            raise ProcessingError(
                                f"Image loading failed: {tile['filename']}",
                                operation="image_loading",
                                cause=e
                            )

                    # crop the tiles if requested
                    if crop_tiles:
                        try:
                            img_batch = [crop(img) for img in img_batch]
                        except Exception as e:
                            logger.error(f"Image cropping failed: {e}")
                            raise ProcessingError(
                                "Image cropping operation failed",
                                operation="image_cropping",
                                cause=e
                            )

                    # retain a copy of the images
                    if secondary is not None:
                        img_batch2 = [img.copy() for img in img_batch]
                    else:
                        img_batch2 = [None] * len(img_batch)

                    # detect with semaphore protection
                    with self.semaphore:  # limit the number of jobs going on in parallel, because of GPU mem
                        try:
                            result_obj = self.model(img_batch)
                        except Exception as e:
                            logger.error(f"YOLOv5 model inference failed: {e}")
                            raise ProcessingError(
                                f"Model inference failed: {str(e)}",
                                operation="yolo_inference",
                                tile_count=len(tile_batch),
                                cause=e
                            )

                        # check for exit signal
                        if events.query(id):
                            logger.info("Detection aborted by user request")
                            return []

                    # get the important part
                    results_raw = result_obj.xyxyn

                    # result is tile by tile
                    for (tile, img, result) in zip(tile_batch, img_batch2, results_raw):
                        try:
                            results_cpu = result.cpu().numpy().tolist()

                            # secondary classifier processing
                            if secondary is not None:
                                try:
                                    # classifier will append its own prob to every detection
                                    secondary.classify(img, results_cpu, batch_id=count)
                                    count += 1
                                except Exception as e:
                                    logger.error(f"Secondary classifier failed: {e}")
                                    # Continue without secondary classification
                                    count += 1

                            tile_results = [{
                                'x1': item[0],
                                'y1':item[1],
                                'x2':item[2],
                                'y2':item[3],
                                'conf':item[4],
                                'class':int(item[5]),
                                'class_name':result_obj.names[int(item[5])],
                                'secondary':item[6] if len(item) > 6 else 1
                                } for item in results_cpu]
                            results.append(tile_results)

                            # record the detections in the tile
                            boxes = []
                            for tr in tile_results:
                                box = "0 " + \
                                    str((tr['x1']+tr['x2'])/2) + \
                                    " "+str((tr['y1']+tr['y2'])/2) + \
                                    " "+str(tr['x2']-tr['x1']) +\
                                    " "+str(tr['y2']-tr['y1'])+"\n"
                                boxes.append(box)
                            tile['detections'] = boxes
                            
                        except Exception as e:
                            logger.error(f"Result processing failed for tile: {e}")
                            # Continue processing other tiles
                            continue

                    logger.debug(f"Batch {i//self.batch_size + 1}/{chunks} completed")

                    if progress_callback is not None:
                        try:
                            progress_callback(
                                batches_completed=(i // self.batch_size) + 1,
                                batches_total=chunks,
                                tiles_processed=min(tile_count, i + len(tile_batch)),
                                tiles_total=tile_count
                            )
                        except Exception as callback_error:
                            logger.debug(f"Progress callback failed: {callback_error}")
                    
                    # Track memory usage after batch (helpful for monitoring memory leaks)
                    if perf_metrics:
                        perf_metrics.update_memory_usage()
                    
                except Exception as e:
                    if isinstance(e, ProcessingError):
                        raise
                    else:
                        logger.error(f"Unexpected error in batch processing: {e}")
                        raise ProcessingError(
                            f"Batch processing failed: {str(e)}",
                            operation="batch_processing",
                            cause=e
                        )

            logger.info(f"YOLOv5 detection completed: {tile_count} tiles processed")
            return results
            
        except Exception as e:
            if isinstance(e, ProcessingError):
                raise
            else:
                logger.error(f"Unexpected error in YOLOv5 detection: {str(e)}", exc_info=True)
                raise ProcessingError(
                    f"YOLOv5 detection system error: {str(e)}",
                    operation="detect",
                    tile_count=len(tiles),
                    cause=e
                )
