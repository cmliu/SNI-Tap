"""应用入口：python -m snitap。"""

from __future__ import annotations

import logging
import sys


def main() -> int:
    """启动 GUI 并进入事件循环。

    Returns:
        进程退出码；Tk 主循环正常结束时为 0。
    """
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    # 必须在 tk.Tk() 之前开启 DPI 感知，create_root() 内部已按此顺序执行
    from snitap.gui.main_window import MainWindow, create_root

    root = create_root()
    window = MainWindow(root)
    window.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
