"""
BasePlugin: The contract all TraceX plugins must satisfy.

A plugin is a Python module placed into the shared plugins volume.
The PluginLoader discovers modules whose top-level class inherits from BasePlugin.

Lifecycle:
    1. Loader calls plugin_class.can_handle(file_path, mime_type) as a class method.
    2. If True, loader instantiates the plugin with context.
    3. Loader calls plugin.setup(), then iterates plugin.parse().
    4. Each yielded dict is a partial ForensicEvent document.
    5. Loader calls plugin.teardown() when done.
"""
from __future__ import annotations

import abc
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, ClassVar, Generator


logger = logging.getLogger(__name__)


class PluginError(Exception):
    """Base class for plugin errors."""


class PluginParseError(PluginError):
    """Raised when parsing a specific record fails but processing can continue."""


class PluginFatalError(PluginError):
    """Raised when the plugin cannot process the file at all."""


@dataclass
class PluginContext:
    """Injected into every plugin instance. Provides access to platform resources."""
    case_id: str
    job_id: str
    source_file_path: Path
    source_minio_url: str
    config: dict[str, Any] = field(default_factory=dict)
    logger: logging.Logger = field(default_factory=lambda: logging.getLogger("plugin"))


class BasePlugin(abc.ABC):
    """
    Abstract base class for all TraceX artifact parsers.

    Subclass this, implement the abstract methods, and drop the module into
    the plugins volume. No further registration is required.
    """

    PLUGIN_NAME: ClassVar[str] = "base"
    PLUGIN_VERSION: ClassVar[str] = "0.0.0"
    DEFAULT_ARTIFACT_TYPE: ClassVar[str] = "generic"
    SUPPORTED_EXTENSIONS: ClassVar[list[str]] = []
    SUPPORTED_MIME_TYPES: ClassVar[list[str]] = []
    # Higher value = tried first. Specific parsers should use 100; generic
    # fallbacks (log2timeline, plaso) should use 10 so they never shadow
    # a dedicated plugin.
    PLUGIN_PRIORITY: ClassVar[int] = 50

    def __init__(self, context: PluginContext) -> None:
        self.ctx = context
        self.log = context.logger.getChild(self.PLUGIN_NAME)

    @classmethod
    def can_handle(cls, file_path: Path, mime_type: str) -> bool:
        """Return True if this plugin can parse the given file."""
        ext_match = file_path.suffix.lower() in cls.SUPPORTED_EXTENSIONS
        mime_match = mime_type in cls.SUPPORTED_MIME_TYPES
        # For files without extension (e.g., $MFT), allow filename matching
        name_match = file_path.name.upper() in cls.get_handled_filenames()
        return ext_match or mime_match or name_match

    @classmethod
    def get_handled_filenames(cls) -> list[str]:
        """Override to handle files matched by name (e.g., '$MFT', 'NTUSER.DAT')."""
        return []

    @classmethod
    def get_info(cls) -> dict[str, Any]:
        """Return plugin metadata for the /api/v1/plugins endpoint."""
        return {
            "name": cls.PLUGIN_NAME,
            "version": cls.PLUGIN_VERSION,
            "default_artifact_type": cls.DEFAULT_ARTIFACT_TYPE,
            "supported_extensions": cls.SUPPORTED_EXTENSIONS,
            "supported_mime_types": cls.SUPPORTED_MIME_TYPES,
            "handled_filenames": cls.get_handled_filenames(),
        }

    @abc.abstractmethod
    def parse(self) -> Generator[dict[str, Any], None, None]:
        """
        Parse the artifact and yield normalized event dicts.

        Required keys in each yielded dict:
            - "timestamp" (str, ISO8601 UTC)
            - "message"   (str, human-readable summary)

        Optional but recommended:
            - "artifact_type"  (str) — overrides DEFAULT_ARTIFACT_TYPE
            - "timestamp_desc" (str)
            - "host", "user", "process", "network" (dicts)
            - Artifact-specific sub-object (e.g., "evtx": {...})
            - "raw" (dict) — original parsed data, stored but not indexed

        Raises:
            PluginParseError: For skippable per-record errors.
            PluginFatalError: For file-level fatal errors.
        """
        ...

    def setup(self) -> None:
        """Called once before parse() is iterated. Open file handles here."""

    def teardown(self) -> None:
        """Called once after parse() is exhausted. Close file handles here."""

    def get_stats(self) -> dict[str, Any]:
        """Return plugin-specific statistics after parsing completes."""
        return {}
