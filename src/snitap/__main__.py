"""应用入口：python -m snitap。"""

from __future__ import annotations

import logging
import sys


def main() -> int:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    from PySide6.QtWidgets import QApplication

    from snitap.gui.main_window import MainWindow, apply_default_font

    app = QApplication(sys.argv)
    app.setApplicationName("SNI域名探测器")
    app.setApplicationDisplayName("SNI域名探测器")
    apply_default_font(app)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
