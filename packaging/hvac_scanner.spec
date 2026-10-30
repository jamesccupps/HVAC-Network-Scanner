# PyInstaller spec for the HVAC Network Scanner GUI.
#
# Build:  pyinstaller packaging/hvac_scanner.spec --noconfirm
# Output: dist/HVACNetworkScanner.exe
#
# The point of this is reach. The scanner is stdlib-only precisely so it can be
# dropped on a Windows box without a Python install, and a single signed-ish
# executable is what makes that true for a field tech who is not going to
# install Python on a client's engineering workstation.
#
# PyInstaller is a BUILD dependency only. It never appears at runtime, so the
# zero-dependency property of the package itself is unaffected.

import os
import re

block_cipher = None

# The spec runs with CWD at the project root when invoked as documented.
project_root = os.path.abspath(os.getcwd())

with open(os.path.join(project_root, 'hvac_scanner', '__init__.py'), encoding='utf-8') as f:
    VERSION = re.search(r'__version__ = "([^"]+)"', f.read()).group(1)


def _version_info():
    """File properties (Details tab) for the exe: product name, version,
    copyright. Unsigned binaries with blank properties look even less
    trustworthy than unsigned ones with them filled in."""
    try:
        from PyInstaller.utils.win32.versioninfo import (
            FixedFileInfo, StringFileInfo, StringStruct, StringTable,
            VarFileInfo, VarStruct, VSVersionInfo)
    except ImportError:
        return None
    nums = tuple(int(x) for x in (VERSION.split('.') + ['0'] * 4)[:4])
    return VSVersionInfo(
        ffi=FixedFileInfo(filevers=nums, prodvers=nums),
        kids=[
            StringFileInfo([StringTable('040904B0', [
                StringStruct('CompanyName', 'James Cupps'),
                StringStruct('FileDescription', 'HVAC Network Scanner'),
                StringStruct('FileVersion', VERSION),
                StringStruct('InternalName', 'HVACNetworkScanner'),
                StringStruct('LegalCopyright', 'MIT License'),
                StringStruct('OriginalFilename', 'HVACNetworkScanner.exe'),
                StringStruct('ProductName', 'HVAC Network Scanner'),
                StringStruct('ProductVersion', VERSION),
            ])]),
            VarFileInfo([VarStruct('Translation', [1033, 1200])]),
        ],
    )

a = Analysis(
    [os.path.join(project_root, 'packaging', 'gui_entry.py')],
    pathex=[project_root],
    binaries=[],
    datas=[],
    # tkinter is pulled in automatically, but the scanner imports its own
    # submodules lazily inside functions (device_profiles, netrange, diff,
    # certs), which static analysis does not always follow.
    hiddenimports=[
        'hvac_scanner.bacnet',
        'hvac_scanner.certs',
        'hvac_scanner.cli',
        'hvac_scanner.codec',
        'hvac_scanner.constants',
        'hvac_scanner.device_profiles',
        'hvac_scanner.diff',
        'hvac_scanner.engine',
        'hvac_scanner.fingerprint',
        'hvac_scanner.gui',
        'hvac_scanner.icon',
        'hvac_scanner.knx',
        'hvac_scanner.modbus',
        'hvac_scanner.netrange',
        'hvac_scanner.netsweep',
        'hvac_scanner.p2',
        'hvac_scanner.report',
        'hvac_scanner.services',
        'hvac_scanner.settings',
        'hvac_scanner.snmp',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Trimming what a stdlib-only tool never touches keeps the binary a
    # sensible size to email or drop on a USB stick.
    excludes=[
        'numpy', 'pandas', 'matplotlib', 'scipy', 'PIL', 'PyQt5', 'PySide2',
        'pytest', 'setuptools', 'pip', 'distutils', 'lib2to3', 'pydoc_data',
        'test', 'unittest',
    ],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name='HVACNetworkScanner',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,          # UPX-packed binaries trip a lot of AV heuristics
    upx_exclude=[],
    runtime_tmpdir=None,
    # A GUI app, so no console window. The CLI stays available from a Python
    # install; bundling both would mean either a console flash on the GUI or
    # two executables, and the exe exists for the people who want the GUI.
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # Regenerate with packaging/make_icon.py if the drawing changes.
    icon=os.path.join(project_root, 'packaging', 'hvac_scanner.ico'),
    version=_version_info(),
)
