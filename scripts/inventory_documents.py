"""Compatible CLI for the packaged metadata inventory engine."""
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from bfrs.application.document_inventory import *  # noqa: F403

if __name__ == '__main__':
    raise SystemExit(main())
