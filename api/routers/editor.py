"""
Custom Code Editor API.

Manages custom ingester files (ingester/*_ingester.py) and module files
(modules/*_module.py) that extend the platform without touching the
built-in plugin/module directories.

Directory layout (both mounted as Docker volumes):
  /app/ingester/   — custom ingesters; auto-loaded by PluginLoader alongside built-ins
  /app/modules/    — custom modules;   auto-loaded by module_task at run time
"""
from __future__ import annotations

import os
import py_compile
import tempfile
from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(tags=["editor"])

INGESTER_DIR      = Path(os.getenv("INGESTER_DIR",  "/app/ingester"))
MODULES_DIR       = Path(os.getenv("MODULES_DIR",   "/app/modules"))
PLUGINS_DIR       = Path(os.getenv("PLUGINS_DIR",   "/app/plugins"))
MODULES_REG_DIR   = Path(__file__).parent.parent / "modules_registry"

INGESTER_SUFFIX = "_ingester.py"
MODULE_SUFFIX   = "_module.py"
PLUGIN_SUFFIX   = "_plugin.py"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _ensure(d: Path) -> None:
    d.mkdir(parents=True, exist_ok=True)


def _safe(base: Path, name: str, suffix: str) -> Path:
    if not name.endswith(suffix):
        raise HTTPException(400, f"File name must end with '{suffix}'")
    if any(c in name for c in ("/", "\\", "..")):
        raise HTTPException(400, "Invalid file name")
    return base / name


def _list(directory: Path, suffix: str) -> list[dict]:
    _ensure(directory)
    out = []
    for f in sorted(directory.glob(f"*{suffix}")):
        out.append({
            "name":     f.name,
            "size":     f.stat().st_size,
            "modified": f.stat().st_mtime,
        })
    return out


def _list_recursive(directory: Path, suffix: str) -> list[dict]:
    """Recursive version — returns relative paths for files in subdirectories."""
    if not directory.exists():
        return []
    out = []
    for f in sorted(directory.rglob(f"*{suffix}")):
        if "__pycache__" in f.parts:
            continue
        rel = f.relative_to(directory).as_posix()
        out.append({
            "name":     rel,
            "size":     f.stat().st_size,
            "modified": f.stat().st_mtime,
        })
    return out


def _safe_plugin(base: Path, name: str, suffix: str) -> Path:
    """Resolve a relative plugin path safely (allows subdirs, blocks traversal)."""
    if ".." in name or name.startswith("/"):
        raise HTTPException(400, "Invalid file path")
    if not name.endswith(suffix):
        raise HTTPException(400, f"File name must end with '{suffix}'")
    return base / name


def _read(path: Path) -> str:
    if not path.exists():
        raise HTTPException(404, "File not found")
    return path.read_text(encoding="utf-8")


def _write(path: Path, content: str) -> None:
    _ensure(path.parent)
    path.write_text(content, encoding="utf-8")


def _validate(content: str) -> dict:
    with tempfile.NamedTemporaryFile(suffix=".py", mode="w", delete=False,
                                    encoding="utf-8") as tf:
        tf.write(content)
        tmp = tf.name
    try:
        py_compile.compile(tmp, doraise=True)
        return {"valid": True}
    except py_compile.PyCompileError as exc:
        # Make the error message relative to the actual file (not tmp path)
        msg = str(exc).replace(tmp, "<editor>")
        return {"valid": False, "error": msg}
    finally:
        os.unlink(tmp)


# ── DTOs ───────────────────────────────────────────────────────────────────────

class FileWrite(BaseModel):
    content: str

class ValidateBody(BaseModel):
    content: str


# ── Ingester CRUD ──────────────────────────────────────────────────────────────

@router.get("/editor/ingesters")
def list_ingesters():
    return {"files": _list(INGESTER_DIR, INGESTER_SUFFIX)}


@router.get("/editor/ingesters/{name}")
def get_ingester(name: str):
    path = _safe(INGESTER_DIR, name, INGESTER_SUFFIX)
    return {"name": name, "content": _read(path)}


@router.put("/editor/ingesters/{name}")
def save_ingester(name: str, body: FileWrite):
    path = _safe(INGESTER_DIR, name, INGESTER_SUFFIX)
    _write(path, body.content)
    return {"saved": True, "name": name}


@router.delete("/editor/ingesters/{name}", status_code=204)
def delete_ingester(name: str):
    path = _safe(INGESTER_DIR, name, INGESTER_SUFFIX)
    if not path.exists():
        raise HTTPException(404, "File not found")
    path.unlink()


# ── Module CRUD ────────────────────────────────────────────────────────────────

@router.get("/editor/modules")
def list_modules_editor():
    return {"files": _list(MODULES_DIR, MODULE_SUFFIX)}


@router.get("/editor/modules/{name}")
def get_module_editor(name: str):
    path = _safe(MODULES_DIR, name, MODULE_SUFFIX)
    return {"name": name, "content": _read(path)}


@router.put("/editor/modules/{name}")
def save_module_editor(name: str, body: FileWrite):
    path = _safe(MODULES_DIR, name, MODULE_SUFFIX)
    _write(path, body.content)
    # Invalidate the modules list cache so new/updated modules appear immediately
    try:
        from routers.modules import invalidate_modules_cache
        invalidate_modules_cache()
    except Exception:
        pass
    return {"saved": True, "name": name}


@router.delete("/editor/modules/{name}", status_code=204)
def delete_module_editor(name: str):
    path = _safe(MODULES_DIR, name, MODULE_SUFFIX)
    if not path.exists():
        raise HTTPException(404, "File not found")
    path.unlink()
    try:
        from routers.modules import invalidate_modules_cache
        invalidate_modules_cache()
    except Exception:
        pass


# ── Built-in ingester plugin files (editable) ─────────────────────────────────

@router.get("/editor/builtin-ingesters")
def list_builtin_ingesters():
    """List built-in plugin Python files (recursive — plugins live in subdirs)."""
    return {"files": [dict(f, builtin=True) for f in _list_recursive(PLUGINS_DIR, PLUGIN_SUFFIX)]}


@router.get("/editor/builtin-ingesters/{name:path}")
def get_builtin_ingester(name: str):
    path = _safe_plugin(PLUGINS_DIR, name, PLUGIN_SUFFIX)
    return {"name": name, "content": _read(path), "builtin": True}


@router.put("/editor/builtin-ingesters/{name:path}")
def save_builtin_ingester(name: str, body: FileWrite):
    """Overwrite a built-in plugin file on the plugins PVC."""
    path = _safe_plugin(PLUGINS_DIR, name, PLUGIN_SUFFIX)
    _write(path, body.content)
    return {"saved": True, "name": name, "builtin": True}


@router.delete("/editor/builtin-ingesters/{name:path}", status_code=204)
def delete_builtin_ingester(name: str):
    """Delete a built-in plugin file from the plugins PVC."""
    path = _safe_plugin(PLUGINS_DIR, name, PLUGIN_SUFFIX)
    if not path.exists():
        raise HTTPException(404, "File not found")
    path.unlink()


# ── Built-in module YAML registry files (editable) ────────────────────────────

def _safe_yaml(name: str) -> Path:
    if not name.endswith(".yaml") or any(c in name for c in ("/", "\\", "..")):
        raise HTTPException(400, "Invalid file name — must end with .yaml")
    return MODULES_REG_DIR / name


@router.get("/editor/builtin-modules")
def list_builtin_modules():
    """List module YAML registry files."""
    if not MODULES_REG_DIR.exists():
        return {"files": []}
    files = []
    for f in sorted(MODULES_REG_DIR.glob("*.yaml")):
        files.append({"name": f.name, "size": f.stat().st_size, "modified": f.stat().st_mtime, "builtin": True})
    return {"files": files}


@router.get("/editor/builtin-modules/{name}")
def get_builtin_module_file(name: str):
    path = _safe_yaml(name)
    if not path.exists():
        raise HTTPException(404, "File not found")
    return {"name": name, "content": path.read_text(encoding="utf-8"), "builtin": True}


@router.put("/editor/builtin-modules/{name}")
def save_builtin_module_file(name: str, body: FileWrite):
    """Overwrite a module YAML registry file."""
    _ensure(MODULES_REG_DIR)
    path = _safe_yaml(name)
    path.write_text(body.content, encoding="utf-8")
    return {"saved": True, "name": name, "builtin": True}


@router.delete("/editor/builtin-modules/{name}", status_code=204)
def delete_builtin_module_file(name: str):
    """Delete a module YAML registry file."""
    path = _safe_yaml(name)
    if not path.exists():
        raise HTTPException(404, "File not found")
    path.unlink()


# ── Shared: syntax validation ──────────────────────────────────────────────────

@router.post("/editor/validate")
def validate_syntax(body: ValidateBody):
    """Check Python syntax without executing. Returns {valid, error?}."""
    return _validate(body.content)
