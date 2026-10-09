"""Private temporary sequences for streaming large folder reports.

Pickle is used only for values produced in this process, never external files.
The list subclass lets json.dump stream arrays without changing report schema.
"""
from __future__ import annotations

import pickle
import sqlite3
import tempfile
from pathlib import Path


class DiskList(list):
    def __init__(self, *, directory=None):
        super().__init__()
        self._temporary = tempfile.TemporaryDirectory(prefix="bfrs-results-", dir=directory)
        self._db = sqlite3.connect(Path(self._temporary.name) / "rows.sqlite")
        self._db.execute("PRAGMA cache_size=-2048")
        self._db.execute("PRAGMA temp_store=FILE")
        self._db.execute("CREATE TABLE rows (id INTEGER PRIMARY KEY, payload BLOB, k0, k1, k2, k3, k4)")
        self._count = 0
        self._ordered = False

    def append(self, value):
        self._db.execute("INSERT INTO rows(payload) VALUES (?)", (pickle.dumps(value),))
        self._count += 1
        if self._count % 128 == 0:
            self._db.commit()

    def extend(self, values):
        for value in values:
            self.append(value)

    def __len__(self):
        return self._count

    def __iter__(self):
        order = "k0, k1, k2, k3, k4, id" if self._ordered else "id"
        cursor = self._db.execute(f"SELECT payload FROM rows ORDER BY {order}")
        try:
            for (payload,) in cursor:
                yield pickle.loads(payload)
        finally:
            cursor.close()

    def sort(self, *, key):
        cursor = self._db.execute("SELECT id, payload FROM rows ORDER BY id")
        try:
            for row_id, payload in cursor:
                keys = key(pickle.loads(payload))
                if not isinstance(keys, tuple):
                    keys = (keys,)
                if len(keys) > 5:
                    raise ValueError("too many ordering fields")
                keys = keys + (None,) * (5 - len(keys))
                self._db.execute("UPDATE rows SET k0=?, k1=?, k2=?, k3=?, k4=? WHERE id=?", (*keys, row_id))
        finally:
            cursor.close()
        self._db.commit()
        self._ordered = True

    def close(self):
        self._db.close()
        self._temporary.cleanup()
