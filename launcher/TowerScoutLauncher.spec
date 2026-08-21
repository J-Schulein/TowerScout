# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path

launcher_root = Path(SPEC).resolve().parent
runtime_policy_path = launcher_root / "towerscout_launcher" / "runtime-policy.v1.json"

analysis = Analysis(
    [str(launcher_root / "towerscout_launcher" / "__main__.py")],
    pathex=[str(launcher_root)],
    binaries=[],
    datas=[(str(runtime_policy_path), "towerscout_launcher")],
    hiddenimports=["tkinter", "tkinter.messagebox", "tkinter.ttk"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "unittest"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(analysis.pure)

exe = EXE(
    pyz,
    analysis.scripts,
    [],
    exclude_binaries=True,
    name="TowerScoutLauncher",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch="x86_64",
    codesign_identity=None,
    entitlements_file=None,
)
collection = COLLECT(
    exe,
    analysis.binaries,
    analysis.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="TowerScoutLauncher",
)
