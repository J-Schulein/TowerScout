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
from urllib.error import URLError

import torch
from PIL import Image

from ts_imgutil import crop
from ts_errors import ModelLoadError, ProcessingError, ResourceError
from ts_logging import get_ml_logger

logger = get_ml_logger()

YOLOV5_HUB_REPO = 'ultralytics/yolov5'
YOLOV5_HUB_REF = '1d62daa3c6b8ec15fdb319c0a2e341d8b56ec86c'
YOLOV5_HUB_SPEC = f'{YOLOV5_HUB_REPO}:{YOLOV5_HUB_REF}'
YOLOV5_HUB_CACHE_PREFIX = 'ultralytics_yolov5_'
YOLOV5_HUB_PINNED_CACHE_DIR = f'{YOLOV5_HUB_CACHE_PREFIX}{YOLOV5_HUB_REF}'
YOLOV5_STALE_IMPORT_SIGNATURE = 'import pkg_resources as pkg'
YOLOV5_HUB_ARCHIVES = ('master.zip', 'main.zip')
YOLOV5_HUB_PINNED_ARCHIVE = f'{YOLOV5_HUB_REF}.zip'
YOLOV5_CACHE_REFRESH_HINT = 'Cache may be out of date, try `force_reload=True`'


def _iter_error_chain(error):
    """Yield an exception and its chained causes/contexts once each."""
    current = error
    seen = set()

    while current is not None and id(current) not in seen:
        yield current
        seen.add(id(current))
        current = current.__cause__ or current.__context__


def _is_pkg_resources_missing_error(error):
    """Detect the stale-cache failure mode caused by old YOLOv5 Hub snapshots."""
    for current in _iter_error_chain(error):
        if isinstance(current, ModuleNotFoundError) and getattr(current, 'name', None) == 'pkg_resources':
            return True

        if "No module named 'pkg_resources'" in str(current):
            return True

    return False


def _is_refreshable_pinned_cache_error(error):
    """Detect cached-repo failures that merit a one-time forced refresh."""
    for current in _iter_error_chain(error):
        if isinstance(current, (ImportError, ModuleNotFoundError, SyntaxError)):
            return True

        if YOLOV5_CACHE_REFRESH_HINT in str(current):
            return True

    return False


def _is_hub_network_error(error):
    """Detect first-run or refresh failures caused by missing GitHub/network access."""
    network_snippets = (
        'Cannot find repo under',
        'No connection could be made',
        'Failed to establish a new connection',
        'Name or service not known',
        'Temporary failure in name resolution',
        'Connection refused',
        'Connection reset',
        'timed out',
    )

    for current in _iter_error_chain(error):
        if isinstance(current, URLError):
            return True

        current_text = str(current)
        if any(snippet in current_text for snippet in network_snippets):
            return True

    return False


def _find_pinned_yolov5_hub_repos():
    """Return the pinned YOLOv5 Hub repo directory if it is already cached."""
    hub_dir = Path(torch.hub.get_dir())
    pinned_repo = hub_dir / YOLOV5_HUB_PINNED_CACHE_DIR

    if pinned_repo.is_dir():
        return hub_dir, [pinned_repo]

    return hub_dir, []


def _find_stale_legacy_yolov5_hub_repos():
    """Return legacy cached YOLOv5 Hub repos that still import pkg_resources."""
    hub_dir = Path(torch.hub.get_dir())
    stale_repos = []

    if not hub_dir.exists():
        return hub_dir, stale_repos

    for repo_dir in hub_dir.glob(f'{YOLOV5_HUB_CACHE_PREFIX}*'):
        if not repo_dir.is_dir():
            continue
        if repo_dir.name == YOLOV5_HUB_PINNED_CACHE_DIR:
            continue

        general_py = repo_dir / 'utils' / 'general.py'
        try:
            if general_py.exists() and YOLOV5_STALE_IMPORT_SIGNATURE in general_py.read_text(encoding='utf-8', errors='ignore'):
                stale_repos.append(repo_dir)
        except OSError:
            continue

    return hub_dir, stale_repos


def _clear_yolov5_hub_repos(hub_dir, repo_dirs, archive_names):
    """Remove Hub repos and matching zip archives."""
    for repo_dir in repo_dirs:
        shutil.rmtree(repo_dir)

    for archive_name in archive_names:
        archive_path = hub_dir / archive_name
        if archive_path.exists():
            archive_path.unlink()


def _clear_pinned_yolov5_hub_repos(hub_dir, pinned_repos):
    """Clear the cached repo for the pinned YOLOv5 ref so it can be refreshed."""
    _clear_yolov5_hub_repos(hub_dir, pinned_repos, (YOLOV5_HUB_PINNED_ARCHIVE,))


def _clear_stale_legacy_yolov5_hub_repos(hub_dir, stale_repos):
    """Clear legacy pkg_resources-era YOLOv5 Hub caches for compatibility hygiene."""
    _clear_yolov5_hub_repos(hub_dir, stale_repos, YOLOV5_HUB_ARCHIVES)


def _load_pinned_yolov5_model(filename, force_reload=False):
    """Load TowerScout's pinned YOLOv5 Hub ref."""
    return torch.hub.load(
        YOLOV5_HUB_SPEC,
        'custom',
        path=filename,
        force_reload=force_reload,
        trust_repo=True,
    )


def _load_model_with_cache_recovery(filename):
    """Load TowerScout's pinned YOLOv5 ref with one bounded cache refresh retry."""
    try:
        return _load_pinned_yolov5_model(filename)
    except Exception as first_error:
        hub_dir, pinned_repos = _find_pinned_yolov5_hub_repos()
        if pinned_repos and _is_refreshable_pinned_cache_error(first_error):
            pinned_repo_list = ', '.join(str(path) for path in pinned_repos)
            logger.warning(
                "Pinned YOLOv5 Torch Hub cache for ref %s failed to load. "
                "Clearing cache and retrying fresh load: %s",
                YOLOV5_HUB_REF,
                pinned_repo_list,
            )

            try:
                _clear_pinned_yolov5_hub_repos(hub_dir, pinned_repos)
            except OSError as clear_error:
                raise RuntimeError(
                    f"Detected invalid cached YOLOv5 Torch Hub ref {YOLOV5_HUB_REF}, "
                    f"but failed to clear it: {clear_error}"
                ) from clear_error

            try:
                return _load_pinned_yolov5_model(filename, force_reload=True)
            except Exception as retry_error:
                raise RuntimeError(
                    f"Failed to load pinned YOLOv5 Torch Hub ref {YOLOV5_HUB_REF} from cache. "
                    f"Cleared cached repo under {hub_dir} and retried a fresh GitHub download, "
                    f"but reload failed: {retry_error}"
                ) from retry_error

        if _is_pkg_resources_missing_error(first_error):
            hub_dir, stale_repos = _find_stale_legacy_yolov5_hub_repos()
            if stale_repos:
                stale_repo_list = ', '.join(str(path) for path in stale_repos)
                logger.warning(
                    "Detected stale legacy YOLOv5 Torch Hub repo requiring pkg_resources. "
                    "Clearing legacy cache and retrying pinned ref load: %s",
                    stale_repo_list
                )

                try:
                    _clear_stale_legacy_yolov5_hub_repos(hub_dir, stale_repos)
                except OSError as clear_error:
                    raise RuntimeError(
                        "Detected stale legacy YOLOv5 Torch Hub repo that requires pkg_resources, "
                        f"but failed to clear it: {clear_error}"
                    ) from clear_error

                try:
                    return _load_pinned_yolov5_model(filename, force_reload=True)
                except Exception as retry_error:
                    raise RuntimeError(
                        "Detected stale legacy YOLOv5 Torch Hub repo that required pkg_resources. "
                        f"Cleared legacy cache under {hub_dir} and retried the pinned ref "
                        f"{YOLOV5_HUB_REF}, but reload failed: {retry_error}"
                    ) from retry_error

        if not pinned_repos and _is_hub_network_error(first_error):
            raise RuntimeError(
                f"Failed to load pinned YOLOv5 Torch Hub ref {YOLOV5_HUB_REF}. "
                f"No cached copy was available under {hub_dir}, and TowerScout could not reach GitHub "
                "to download it. GitHub/network access is required the first time this pinned ref is "
                f"downloaded or whenever TowerScout must refresh that cache: {first_error}"
            ) from first_error

        raise


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
