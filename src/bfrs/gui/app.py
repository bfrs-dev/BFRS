"""Desktop entry point for BFRS."""

from __future__ import annotations

import sys


def main() -> int:
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError as error:
        print(
            "BFRS GUI wymaga opcjonalnego pakietu PySide6. "
            "Zainstaluj: py -m pip install -e '.[gui]'",
            file=sys.stderr,
        )
        return 2

    from bfrs.gui.main_window import MainWindow

    application = QApplication.instance() or QApplication(sys.argv)
    application.setApplicationName("BFRS")
    window = MainWindow()
    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
