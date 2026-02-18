import logging

from mwdb.core.plugins import PluginAppContext
from .hook import ClamYaraHookHandler

__author__ = "Askar Dyussekeyev"
__version__ = "0.0.2"
__doc__ = "Local plugin for MWDB that scans (re-)uploaded files using ClamAV and YARA"

logger = logging.getLogger("mwdb.plugin.clamyara")


def entrypoint(app_context: PluginAppContext):
    """
    Register plugin hook handler.
    """
    app_context.register_hook_handler(ClamYaraHookHandler)
    logger.info("ClamYara plugin hook handler registered")


__plugin_entrypoint__ = entrypoint
