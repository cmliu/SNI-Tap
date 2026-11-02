# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置（单文件 exe，GUI 已迁移到标准库 tkinter）。

用法：
    pyinstaller snitap.spec
产物：dist/SNI-Tap.exe

技术栈从 PySide6 换成 tkinter 之后，原先的 Qt 组件裁剪逻辑全部作废；
现在的体积主要由 Tcl/Tk 运行时构成（tcl86t.dll / tk86t.dll + tcl8.6
脚本库约 2-3 MB），其余是 CPython 解释器与本项目代码。

excludes 只剔除「本应用确定用不到」的标准库：GUI 只用 tkinter，网络只用
asyncio/socket，没有任何序列化、数据库、归档、多进程、打包工具链的需求。
剔除后必须真实运行 exe 验证，不能只看体积。
"""

a = Analysis(
    ['src/snitap/__main__.py'],
    pathex=['src'],
    binaries=[],
    datas=[('assets/app.ico', 'assets')],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # 测试与文档工具链
        'tkinter.test',
        'test',
        'unittest',
        'doctest',
        'pydoc',
        'lib2to3',
        # 打包 / 安装工具链
        'distutils',
        'setuptools',
        'pip',
        'pkg_resources',
        # 本应用零使用的标准库大件
        'email',
        'http',
        'xml',
        'xmlrpc',
        'multiprocessing',
        'sqlite3',
        'bz2',
        'lzma',
        'tarfile',
        # ssl / _hashlib：本项目不做 TLS（只做字节转发 + ClientHello 明文嗅探），
        # 排除后可连带甩掉 libcrypto-3.dll(1.86MB) 与 libssl-3.dll(0.28MB)。
        # asyncio 对 ssl 是 `try: import ssl / except ImportError: ssl = None`，
        # 缺失时优雅降级，不影响纯 TCP/UDP 转发。
        'ssl',
        '_ssl',
        '_hashlib',
    ],
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
    upx=False,  # 本机未安装 upx，开启只是空转；也不再依赖外部工具链
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    icon='assets/app.ico',
)
