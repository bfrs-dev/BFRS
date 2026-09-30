"""Desktop entry point for BFRS."""

from __future__ import annotations

import multiprocessing
import sys


def _prepare_multiprocessing() -> None:
    """Let frozen Windows worker processes bypass normal GUI startup."""
    multiprocessing.freeze_support()


def main() -> int:
    _prepare_multiprocessing()
    try:
        from PySide6.QtGui import QIcon
        from PySide6.QtWidgets import QApplication
    except ImportError as error:
        print(
            "BFRS GUI wymaga opcjonalnego pakietu PySide6. "
            "Zainstaluj: py -m pip install -e '.[gui]'",
            file=sys.stderr,
        )
        return 2

    from importlib.resources import files

    from bfrs.gui.main_window import MainWindow

    application = QApplication.instance() or QApplication(sys.argv)
    application.setApplicationName("BFRS")
    icon_path = files("bfrs.gui").joinpath("assets", "bfrs.png")
    application.setWindowIcon(QIcon(str(icon_path)))
    window = MainWindow()
    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
