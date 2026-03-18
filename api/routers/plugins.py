"""Plugin management endpoints."""
import sys
from pathlib import Path
from fastapi import APIRouter, HTTPException

from config import settings

router = APIRouter(tags=["plugins"])

# Lazy-load the plugin loader to avoid import issues at startup
_loader = None


def get_loader():
    global _loader
    if _loader is None:
        # Add plugins volume to sys.path
        plugins_path = Path(settings.PLUGINS_DIR)
        parent = str(plugins_path.parent)
        if parent not in sys.path:
            sys.path.insert(0, parent)

        from processor.plugin_loader import PluginLoader
        _loader = PluginLoader(plugins_path)
        _loader.load()
    return _loader


@router.get("/plugins")
def list_plugins():
    """List all loaded plugins from the plugins volume."""
    try:
        loader = get_loader()
        plugins = loader.list_plugins()
        return {"plugins": plugins, "total": len(plugins)}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Plugin discovery failed: {exc}")


@router.post("/plugins/reload")
def reload_plugins():
    """Force a hot-reload of all plugins from the volume."""
    global _loader
    _loader = None
    try:
        loader = get_loader()
        plugins = loader.list_plugins()
        return {
            "message": "Plugins reloaded",
            "plugins": plugins,
            "total": len(plugins),
        }
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Reload failed: {exc}")
