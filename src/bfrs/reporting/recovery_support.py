"""Optional CLI presentation based on the existing public finding states."""
from typing import Any, Iterable, Mapping

from bfrs.reporting.finding_state import (
    CryptoState, DiscoveryState, PublicFindingState, RecoveryRelevance,
    StructuralState, normalize_finding,
)

# PUBLIC_DONATION_ADDRESS: public receiving address, never a recovery secret.
BTC_DONATION_ADDRESS = "bc1qw4yrk7dhc2xcnpneh392xzdp9ey05saaxq8dav"
_SECRET_KINDS = {"private_key", "wif_private_key", "ec_private_key_der", "mnemonic"}
_WALLET_KINDS = {"electrum_wallet", "reconstructed_wallet", "multibit_classic_protobuf",
                 "multibit_classic_legacy", "armory_wallet"}


def should_show_recovery_support_message(findings: Iterable[Mapping[str, Any]]) -> bool:
    """Require validated secrets or accepted complete wallets; exclude noise."""
    for row in findings:
        state = (PublicFindingState(**row["normalized_state"])
                 if "normalized_state" in row else normalize_finding(row))
        if (state.discovery_state in {DiscoveryState.RAW, DiscoveryState.REJECTED}
                or state.recovery_relevance == RecoveryRelevance.LIKELY_FALSE_POSITIVE):
            continue
        kind = str(row.get("artifact_kind", "")).lower()
        if kind in _SECRET_KINDS and state.crypto_state == CryptoState.VALID:
            return True
        if (kind in _WALLET_KINDS
                and state.discovery_state == DiscoveryState.ACCEPTED
                and state.structural_state == StructuralState.COMPLETE):
            return True
    return False


def recovery_support_findings(report: Mapping[str, Any]):
    """Select final recovery views, preserving their existing normalized state.

    Section identity supplies artifact types absent from legacy report rows.
    Database pages, records, anchors and aggregate counters are not wallets.
    """
    yield from report.get("target_findings", ())
    for section, kind in (("mnemonic_recovery", "mnemonic"),
                          ("electrum_raw_recovery", "electrum_wallet")):
        for row in report.get(section, {}).get("candidates", ()):
            yield {**row, "artifact_kind": kind}
    for row in report.get("reconstructed_wallet_results", ()):
        yield {**row, "artifact_kind": "reconstructed_wallet"}
    for wallet in report.get("legacy_wallet_recovery", {}).get("candidates", ()):
        state = wallet.get("normalized_state", {})
        if (state.get("discovery_state") == DiscoveryState.REJECTED
                or state.get("recovery_relevance") == RecoveryRelevance.LIKELY_FALSE_POSITIVE):
            continue
        for row in wallet.get("crypto_validation_results", ()):
            yield {**row, "artifact_kind": "private_key"}


def render_recovery_support_message() -> str:
    """Static text only: deliberately accepts no findings or recovered values."""
    return f"""============================================================
BFRS 2.0 — RECOVERY SUCCESS
============================================================

BFRS found validated recovery material.

If BFRS helped you recover a wallet, private key, or seed,
and you would like to support further development, you can
make a voluntary Bitcoin donation:

BTC:
{BTC_DONATION_ADDRESS}

Donations are completely optional and have no effect on
recovery, validation, or access to results.

Security reminder:
Recovered private keys or seeds should be treated as potentially
exposed. After confirming access to the recovered funds, consider
moving them to a new securely backed-up wallet.

============================================================"""


def print_recovery_support_message(report: Mapping[str, Any]) -> None:
    """Called once after the final summary of each successful CLI scan."""
    if should_show_recovery_support_message(recovery_support_findings(report)):
        print(render_recovery_support_message())
