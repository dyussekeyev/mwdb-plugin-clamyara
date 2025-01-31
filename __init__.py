import logging
import requests
import subprocess
import re
import os
from datetime import datetime

from mwdb.core.plugins import PluginAppContext, PluginHookHandler
from mwdb.model import File
from mwdblib import MWDB

__author__ = "Askar Dyussekeyev"
__version__ = "0.0.2"
__doc__ = "Local plugin for MWDB that scans (re-)uploaded using ClamAV and Yara"

logger = logging.getLogger("mwdb.plugin.clamyara")

config_api_url = ""
config_api_key = ""
SCAN_DIR = '/tmp/share'
YARA_RULES_FILE = "yara-rules-full.yar"

if not os.path.exists(SCAN_DIR):
    os.makedirs(SCAN_DIR)

def ClamScan(directory, filename):
    """Runs the clamdscan program with specified parameters."""
    result = subprocess.run(
        ["clamdscan", directory], 
        capture_output=True, text=True
    )

    if "ERROR" in result.stdout:
        return "Error"
    match = re.search(r'{}: (.*) FOUND'.format(re.escape(filename)), result.stdout)
    if match:
        return match.group(1)
    return "Undetected"

def ClamParse(output, filename):
    """Parses the output to find the threat for the specified file."""
    if "ERROR" in output:
        return "Error"
    match = re.search(r'{}: (.*) FOUND'.format(re.escape(filename)), output)
    if match:
        return match.group(1)
    return "Undetected"

def ClamVersion():
    """Gets the ClamAV version and signature database information."""
    result = subprocess.run(
        ["clamdscan", "--version"],
        capture_output=True, text=True
    )
    return result.stdout.strip()

def YaraScan(file_path):
    """Runs the yara program with specified parameters."""
    result = subprocess.run(
        ["yara", YARA_RULES_FILE, file_path], 
        capture_output=True, text=True
    )
    return result.stdout.strip()

def YaraParse(output):
    """Parses the YARA output to find the rule matches."""
    if not output:
        return "Undetected"
    # Extracting the rule names
    rule_names = [line.split(' ')[0] for line in output.split('\n') if line]
    return rule_names

def ClamYaraAddTag(file, av_name: str, av_result: str):
    for tag in file.tags:
        if tag.lower().startswith(f"{av_name.lower()}:"):
            file.remove_tag(tag)

    file.add_tag(f"{av_name.lower()}:{av_result.lower()}")

def ClamYaraProcessFile(hash_value):
    mwdb = MWDB(api_url=config_api_url, api_key=config_api_key)
    file = mwdb.query_file(hash_value)

    temp_file_path = f"{SCAN_DIR}/{hash_value}"
    with open(temp_file_path, "wb") as f:
        f.write(file.content)

    comment = ""

    # Scan with ClamAV
    cl_result = ClamScan(SCAN_DIR, hash_value)
    cl_version = ClamVersion()
    comment += f"ClamAV: {cl_result} (Version: {cl_version})\n"
    
    # Scan with Yara
    yara_result = YaraScan(temp_file_path)
    yara_matches = YaraParse(yara_result)
    comment += f"YARA Matches: {', '.join(yara_matches)}\n" if yara_matches != "Undetected" else "YARA: Undetected\n"
    
    # Add results
    file.add_comment(comment.strip())
    if cl_result != 'Error' and cl_result != 'Undetected':
        ClamYaraAddTag(file, 'clamav', cl_result)
    if yara_matches != "Undetected":
        for match in yara_matches:
            ClamYaraAddTag(file, 'yara', match)
    
    # Remove the temporary file
    os.remove(temp_file_path)

class ClamYaraHookHandler(PluginHookHandler):
    def on_created_file(self, file: File):
        logger.info("on_created_file(): Scan requested for sha256 = %s", file.sha256)
        ClamYaraProcessFile(file.sha256)

    def on_reuploaded_file(self, file: File):
        logger.info("on_reuploaded_file(): Scan requested for sha256 = %s", file.sha256)
        ClamYaraProcessFile(file.sha256)

def entrypoint(app_context: PluginAppContext):
    """
    Register plugin hook handler.

    This will be called on app load.
    """
    app_context.register_hook_handler(ClamYaraHookHandler)
    logger.info("Plugin hook handler is registered.")

__plugin_entrypoint__ = entrypoint
