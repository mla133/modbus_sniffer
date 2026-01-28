# -*- mode: python ; coding: utf-8 -*-

# Tuned PyInstaller spec for a small, reliable EXE build.
# Build command: pyinstaller modbus-sniffer.spec -y
# Adjust paths (e.g., upx=True) or excludes as needed.

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_submodules

# Project entry (your CLI dispatcher)
ENTRY_SCRIPT = "main.py"
APP_NAME = "modbus-sniffer"

# Optional: keep dist/work paths predictable
DISTPATH = str(Path("dist").resolve())
WORKPATH = str(Path("build").resolve())

# Hidden imports:
# - If PyInstaller misses dynamic modules, add them here.
#   Start with zero; only add what you actually need.
hidden_imports = [
    # Example (uncomment if needed):
    # "pyshark", "pyshark.tshark.tshark",
]

# Exclude modules you don't use to save space.
# Remove an item if your build needs it.
excludes = [
    "tkinter",
    "PyQt5", "PyQt6", "PySide2", "PySide6",
    "pytest", "unittest",
    # Scientific stacks are large; exclude if unused:
    "numpy", "scipy",
    # Dev tools
    "pydoc",
]

# Analysis:
# - strip: remove symbol tables (smaller size; OK for Windows CLI)
# - optimize: 1 (remove asserts) or 2 (also removes docstrings)
# - upx: enable UPX compression if UPX is installed
a = Analysis(
    scripts=[ENTRY_SCRIPT],
    pathex=[str(Path(".").resolve())],
    binaries=[],
    datas=[],
    hiddenimports=hidden_imports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=excludes,
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=None,
    noarchive=False,  # keep archive to allow UPX compression of contents
)

# PYZ: Python bytecode archive
pyz = PYZ(
    a.pure,
    a.zipped_data,
    cipher=None,
)

# EXE (bootloader & main)
exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name=APP_NAME,
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,        # strip symbols -> smaller size (Windows effect is modest)
    upx=True,          # compress with UPX (requires UPX installed)
    upx_exclude=[],    # add names to skip UPX if needed
    console=True,      # CLI tool -> True; change to False for GUI
    disable_windowed_traceback=False,
    target_arch=None,
)

# COLLECT stage (for --onedir). We keep a onefile here by converting with single EXE block below.
# If you prefer --onedir, replace the final "onefile" stage with "coll = COLLECT(...)" and comment out the PKG part.
# For onefile packaging, we generate PKG ➜ run-time extraction (PyInstaller bootloader behavior).

# PKG stage (onefile): bundle everything into a single exe
# distpath/workpath are set above to keep output clean.
# Note: onefile EXE extracts itself to a temp folder on start (normal behavior).
#       If you embed large data, consider --onedir to keep startup snappy.
pkg = PKG(
    exe,
    name=APP_NAME,
    # By default, PyInstaller writes to ./dist and ./build; we override here.
    # If you prefer command-line overrides, you can drop these parameters.
    distpath=DISTPATH,
    workpath=WORKPATH,
    # Clean room options:
    # 'crypto' and additional packaging tweaks may be placed here if needed.
)
