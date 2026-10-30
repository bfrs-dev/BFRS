"""Bounded filename clues, never evidence of wallet contents or ownership."""
from __future__ import annotations

MAX_HINTS = 50
MAX_HINT_NAME = 512
WALLET_TERMS = ('wallet', 'electrum', 'bitcoin', 'portfel')
BACKUP_TERMS = ('backup',)


def name_hint(name):
    folded = name.casefold()
    wallet = [term for term in WALLET_TERMS if term in folded]
    backup = [term for term in BACKUP_TERMS if term in folded]
    if not wallet and not backup:
        return None
    return {'name': name[:MAX_HINT_NAME], 'name_truncated': len(name) > MAX_HINT_NAME,
            'terms': wallet + backup, 'category': 'WALLET_NAME' if wallet else 'BACKUP_NAME'}


class NameHints:
    """Check all visited names; retain stronger clues ahead of generic backups."""
    def __init__(self):
        self.checked = self.matched = self.wallet_count = self.encrypted_wallet_count = 0
        self.wallet = []
        self.backup = []

    def add(self, name, *, header_offset, member_index, encrypted=None):
        self.checked += 1
        hint = name_hint(name)
        if hint is None:
            return
        self.matched += 1
        wallet = hint['category'] == 'WALLET_NAME'
        self.wallet_count += wallet
        self.encrypted_wallet_count += wallet and encrypted is True
        target = self.wallet if wallet else self.backup
        if len(target) < MAX_HINTS:
            target.append({**hint, 'header_offset': header_offset, 'member_index': member_index,
                           'encryption_indicator': encrypted})

    def report(self, *, complete=False):
        matches = (self.wallet + self.backup)[:MAX_HINTS]
        return {'zip_name_hints': matches, 'zip_names_checked_for_hints': self.checked,
                'zip_name_hint_count': self.matched, 'zip_wallet_name_hint_count': self.wallet_count,
                'zip_encrypted_wallet_name_hint_count': self.encrypted_wallet_count,
                'zip_name_hints_truncated': self.matched > len(matches),
                'zip_name_hints_complete': complete,
                'zip_name_hint_scope': 'METADATA_NAMES_ONLY_NOT_WALLET_VALIDATION'}
