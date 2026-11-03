# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller 打包配置（单文件 exe，GUI 已迁移到标准库 tkinter）。

用法：
    pyinstaller snitap.spec
产物：dist/SNI-Tap.exe

技术栈从 PySide6 换成 tkinter 之后，原先的 Qt 组件裁剪逻辑全部作废；
现在的体积主要由 Tcl/Tk 运行时构成（tcl86t.dll / tk86t.dll + tcl8.6
脚本库约 2-3 MB），其余是 CPython 解释器与本项目代码。

v2 起 QUIC Initial 解密依赖 cryptography，OpenSSL 的 libcrypto 会随包打入，
单文件体积预期从约 9.1 MB 增长到 14~16 MB。因此：
- 解除 ssl / _ssl / _hashlib 的排除（cryptography 依赖 _ssl / _hashlib）；
- hiddenimports 显式声明 cryptography 的懒加载子模块（quic_crypto 在函数
  内 import，静态分析扫不到，必须在这里兜底）。

excludes 仍剔除「本应用确定用不到」的标准库：GUI 只用 tkinter，网络只用
asyncio/socket。剔除后必须真实运行 exe 验证，不能只看体积。
"""

a = Analysis(
    ['src/snitap/__main__.py'],
    pathex=['src'],
    binaries=[],
    datas=[('assets/app.ico', 'assets')],
    hiddenimports=[
        # quic_crypto.py 在函数内懒加载，PyInstaller 静态分析扫不到，需显式声明
        'cryptography',
        'cryptography.hazmat.primitives.hashes',
        'cryptography.hazmat.primitives.kdf.hkdf',
        'cryptography.hazmat.primitives.ciphers',
        'cryptography.hazmat.primitives.ciphers.aead',
    ],
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
        # 注意：ssl / _ssl / _hashlib 不再排除——cryptography（QUIC 解密）
        # 依赖 _hashlib 与 OpenSSL，排除会导致运行时 ImportError。
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
