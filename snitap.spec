# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置（单文件 exe + Qt 组件裁剪）。

用法：
    pip install pyinstaller
    pyinstaller snitap.spec
产物：dist/SNI-Tap.exe

本应用只用 Qt Widgets（Core/Gui/Widgets），打包前把 PySide6 hook
捆绑进来的无关组件剔除，显著减小体积：
- opengl32sw：软件 OpenGL 渲染后备（7.3 MB），纯窗口应用不需要；
- Qt6Quick/Qml/QmlModels/Pdf/Svg/OpenGL：QML 全家桶，零使用；
- Qt6Network/QtNetwork.pyd + libcrypto/libssl：Qt 网络栈，本项目
  网络逻辑是纯 socket，不走 Qt Network；
- translations：Qt 界面翻译文件（界面文案是自绘中文，不依赖 .qm）；
- 冷门 imageformats 与备用平台插件：保留 qwindows + qico（窗口
  图标 .ico 读取依赖 qico）与 qjpeg/gif。
"""

import fnmatch

# 需要从打包结果中剔除的文件（匹配 PyInstaller 目标路径，/ 分隔）
_TRIM_PATTERNS = [
    "PySide6/opengl32sw.dll",
    "PySide6/Qt6Quick*.dll",
    "PySide6/Qt6Qml*.dll",
    "PySide6/Qt6Pdf*.dll",
    "PySide6/Qt6Svg*.dll",
    "PySide6/Qt6OpenGL*.dll",
    "PySide6/Qt6Network.dll",
    "PySide6/QtNetwork.pyd",
    "libcrypto-*.dll",
    "libssl-*.dll",
    "PySide6/translations/*",
    "PySide6/plugins/imageformats/qtiff.dll",
    "PySide6/plugins/imageformats/qwebp.dll",
    "PySide6/plugins/imageformats/qtga.dll",
    "PySide6/plugins/imageformats/qicns.dll",
    "PySide6/plugins/imageformats/qwbmp.dll",
    "PySide6/plugins/platforms/qdirect2d.dll",
    "PySide6/plugins/networkinformation/*",
    "PySide6/plugins/tls/*",
    "PySide6/plugins/multimedia/*",
    "PySide6/plugins/sqldrivers/*",
    "PySide6/plugins/sceneparsers/*",
    "PySide6/plugins/position/*",
    "PySide6/plugins/sensors/*",
    "PySide6/plugins/qmltooling/*",
    "PySide6/plugins/canbus/*",
    "PySide6/plugins/webview/*",
]


def _trim(items):
    """按模式剔除 (dest, src, kind) 条目；打印剔除清单便于核对。"""
    kept = []
    dropped = []
    for item in items:
        dest = item[0].replace("\\", "/")
        if any(fnmatch.fnmatch(dest, pat) for pat in _TRIM_PATTERNS):
            dropped.append(dest)
        else:
            kept.append(item)
    print(f"[trim] 剔除 {len(dropped)} 项：")
    for name in sorted(dropped):
        print(f"   - {name}")
    return kept


a = Analysis(
    ['src/snitap/__main__.py'],
    pathex=['src'],
    binaries=[],
    datas=[('assets/app.ico', 'assets')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter'],
    noarchive=False,
)
a.binaries = _trim(a.binaries)
a.datas = _trim(a.datas)
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
    icon='assets/app.ico',
)
