"""Open the standalone inventory browser without rescanning source files."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))


def main():
    try:
        from bfrs.gui.inventory_browser import main as run
    except ImportError as error:
        print('Przeglądarka wymaga PySide6. Zainstaluj w tym samym Pythonie:\n'
              'py -3.13 -m pip install "PySide6>=6.11,<7"\n'
              f'Szczegóły: {error}', file=sys.stderr)
        return 2
    return run()


if __name__ == '__main__':
    raise SystemExit(main())
