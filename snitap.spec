# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置（单文件 exe）。

用法：
    pip install pyinstaller
    pyinstaller snitap.spec
产物：dist/SNI-Tap.exe
"""

a = Analysis(
    ['src/snitap/__main__.py'],
    pathex=['src'],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter'],
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='SNI-Tap',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    icon=None,
)
