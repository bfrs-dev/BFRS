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
        from PySide6.QtCore import Qt
        from PySide6.QtGui import QColor, QIcon, QPainter, QPen, QPixmap
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

    pixmap = QPixmap(256, 256)
    pixmap.fill(Qt.GlobalColor.transparent)
    painter = QPainter(pixmap)
    painter.setRenderHint(QPainter.RenderHint.Antialiasing, True)
    navy = QColor(8, 26, 50)
    cyan = QColor(44, 220, 255)
    silver = QColor(205, 225, 238)

    painter.setPen(QPen(QColor(74, 190, 255), 8))
    painter.setBrush(navy)
    painter.drawRoundedRect(20, 20, 216, 216, 40, 40)

    painter.setPen(QPen(cyan, 7))
    painter.setBrush(QColor(12, 42, 78))
    painter.drawRoundedRect(48, 36, 38, 184, 14, 14)
    painter.drawRoundedRect(70, 40, 140, 88, 40, 40)
    painter.drawRoundedRect(70, 128, 140, 88, 40, 40)

    painter.setPen(QPen(QColor(79, 217, 255), 6))
    painter.setBrush(QColor(150, 188, 214))
    painter.drawEllipse(38, 78, 106, 106)
    painter.setPen(QPen(silver, 10))
    painter.setBrush(Qt.BrushStyle.NoBrush)
    painter.drawEllipse(75, 88, 94, 94)
    painter.setPen(QPen(cyan, 5))
    painter.drawEllipse(81, 94, 82, 82)

    painter.setPen(QPen(silver, 14))
    painter.drawLine(145, 158, 205, 218)
    painter.end()
    application.setWindowIcon(QIcon(pixmap))
    window = MainWindow()
    window.show()
    return application.exec()


if __name__ == "__main__":
    raise SystemExit(main())
