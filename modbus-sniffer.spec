# -*- mode: python ; coding: utf-8 -*-

a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[
        "pyshark.tshark.tshark",
        # If you hit pkg_resources/jaraco issues again, you can force:
        # "jaraco.text",
        # "jaraco.functools",
        # "jaraco.collections",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Already excluded
        "tkinter",
        "numpy",
        "pytest",
        "PyQt5",

        # Newly identified removable packages (mostly safe)
        # "lxml",
        "PIL",
        "pygments",
        "chardet",
        "dns",
        "rich",
        "_brotli",
        "pywin32_system32",
        "pycparser",
        "html5lib",

        # DO NOT exclude setuptools here (see explanation below)
        # "setuptools",
    ],
    noarchive=False,
    optimize=2,  # 0=no opt, 1=removes asserts, 2=also removes docstrings
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name='modbus-sniffer',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
