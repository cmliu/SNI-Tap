"""便捷启动入口：python main.py（无需安装，自动把 src 加入模块路径）。"""

from __future__ import annotations

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent / "src"))

from snitap.__main__ import main  # noqa: E402

if __name__ == "__main__":
    raise SystemExit(main())
