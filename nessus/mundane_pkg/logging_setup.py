import os, sys
from pathlib import Path

# ## === Logging setup (Phase 6) ===
# Controlled via env (no CLI changes):
#   MUNDANE_LOG    -> path to log file (default: ~/mundane.log)
#   MUNDANE_DEBUG  -> when set to a truthy value, enables DEBUG (else INFO)
# Keeps console UX the same; logs go to file only.
try:
    from loguru import logger as _log
    _USE_LOGURU = True
except Exception:
    import logging as _logging
    _USE_LOGURU = False

def env_truthy(name: str, default: bool = False) -> bool:
    v = os.environ.get(name)
    if v is None:
        return default
    return v.strip().lower() in {"1","true","yes","y","on"}

def init_logger() -> None:
    global _USE_LOGURU
    log_path = os.environ.get("MUNDANE_LOG") or str(Path.home() / "mundane.log")
    debug = env_truthy("MUNDANE_DEBUG", False)
    level = "DEBUG" if debug else "INFO"
    try:
        if _USE_LOGURU:
            try:
                _log.remove()
            except Exception:
                pass
            _log.add(log_path, level=level, rotation="1 MB", retention=3, enqueue=False, backtrace=False, diagnose=False)
            _log.info("Logger initialized (loguru) at {} with level {}", log_path, level)
        else:
            Path(log_path).parent.mkdir(parents=True, exist_ok=True)
            _logging.basicConfig(
                filename=log_path,
                level=_logging.DEBUG if debug else _logging.INFO,
                format="%(asctime)s %(levelname)s %(message)s",
            )
            _logging.info("Logger initialized (stdlib) at %s with level %s", log_path, level)
    except Exception:
        pass

init_logger()

def log_info(msg: str) -> None:
    try:
        if _USE_LOGURU:
            _log.info(msg)
        else:
            _logging.info(msg)
    except Exception:
        pass

def log_debug(msg: str) -> None:
    try:
        if _USE_LOGURU:
            _log.debug(msg)
        else:
            _logging.debug(msg)
    except Exception:
        pass

def log_error(msg: str) -> None:
    try:
        if _USE_LOGURU:
            _log.error(msg)
        else:
            _logging.error(msg)
    except Exception:
        pass

_orig_excepthook = sys.excepthook
def ex_hook(exc_type, exc, tb):
    try:
        if _USE_LOGURU:
            _log.opt(exception=(exc_type, exc, tb)).error("Unhandled exception")
        else:
            import traceback as _tb
            log_error("Unhandled exception:\n" + "".join(_tb.format_exception(exc_type, exc, tb)))
    except Exception:
        pass
    return _orig_excepthook(exc_type, exc, tb)

sys.excepthook = ex_hook

def log_timing(fn):
    import time, functools
    @functools.wraps(fn)
    def _wrap(*args, **kwargs):
        t0 = time.perf_counter()
        try:
            return fn(*args, **kwargs)
        finally:
            dt = (time.perf_counter() - t0) * 1000.0
            log_debug(f"{fn.__name__} took {dt:.1f} ms")
    return _wrap

# small public wrapper for __init__.py
def setup_logging() -> None:
    init_logger()