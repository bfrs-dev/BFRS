"""Conservative, explicit exact-page export. No record serialization or repair.

V1 supports one outer catalog entry named main and one wallet subdatabase,
with every allocated page accounted for by their trees. Free lists, overflow,
checksummed/encrypted pages and additional subdatabases are refused.
"""
from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import json
import os
from pathlib import Path
import re
import tempfile

from bfrs.core.models import ValidationStatus
from bfrs.core.path_safety import paths_refer_to_same_file
from bfrs.recovery.berkeley_records import BerkeleyLeafRecordExtractor
from bfrs.recovery.logical_berkeley_database_pipeline import LogicalBerkeleyDatabaseRecoveryPipeline
from bfrs.recovery.logical_berkeley_reader import LogicalBerkeleyMetadataAnchor, LogicalBerkeleyPageReader
from bfrs.recovery.logical_btree_membership import LogicalBtreeMembershipResolver
from bfrs.recovery.logical_wallet_record_decoder import LogicalBitcoinWalletRecordDecoderV1, LogicalWalletRecordState
from bfrs.validators.logical_encrypted_wallet_evidence import LogicalBerkeleyRecordPageContext
from bfrs.recovery.logical_page_map import LogicalBerkeleyPageMap, LogicalPageLocation
from bfrs.validators.base import ValidationContext
from bfrs.validators.berkeley_metadata import BerkeleyMetadataValidator, is_valid_page_size
from bfrs.validators.berkeley_page import BerkeleyPageValidator, BTREE_LEAF, BTREE_INTERNAL, KEYDATA
from bfrs.validators.berkeley_page_chain import BerkeleyPageChainValidator
from bfrs.validators.berkeley_page_locator import BerkeleyAnchor


class ExportRefused(Exception):
    """Only fixed reason codes may cross the CLI boundary."""


def require(condition: bool, code: str) -> None:
    if not condition:
        raise ExportRefused(code)


def number(value: object) -> int:
    require(type(value) is int and value >= 0, "INVALID_INTEGER")
    return value


@dataclass(repr=False)
class _Pages:
    data: dict[int, bytes] = field(repr=False)
    size: int

    def read_at(self, offset: int, length: int) -> bytes:
        page, local = divmod(offset, self.size)
        return self.data.get(page, b"")[local:local + length]


@dataclass(repr=False)
class Reconstruction:
    pages: dict[int, bytes] = field(repr=False)
    offsets: dict[int, int]
    page_size: int
    byte_order: str
    metadata_number: int
    root: int
    logical_id: str
    candidate_id: str
    record_counts: dict[str, int]
    crypto_summary: dict[str, int]
    record_pair_count: int


def _metadata(data: bytes, page: int, size: int, order: str) -> dict:
    result = BerkeleyMetadataValidator().validate(ValidationContext("export", page * size, data))
    e = result.evidence
    require(result.status is ValidationStatus.STRUCTURAL and result.start_offset == page * size,
            "INVALID_METADATA")
    require(e.get("page_number") == page and e.get("page_size") == size
            and e.get("byte_order") == order, "METADATA_IDENTITY_MISMATCH")
    # Existing parsers do not verify BDB page checksums or encryption.
    require(data[24] == 0 and data[26] == 0, "UNSUPPORTED_METADATA_FEATURES")
    require(e.get("free_page") == 0, "FREE_LIST_UNSUPPORTED")
    return e


def _complete(db: dict) -> None:
    require(db["status"] == "structural" and
            db["normalized_state"]["structural_state"] == "COMPLETE", "DATABASE_INCOMPLETE")
    for name, code in (("missing_page_numbers", "MISSING_PAGE"),
                       ("ambiguous_page_numbers", "AMBIGUOUS_PAGE"),
                       ("rejected_page_numbers", "REJECTED_PAGE")):
        require(db[name] == [], code)


def _mapping(db: dict, size: int, order: str, source: Path) -> dict[int, int]:
    _complete(db)
    identity = db["identity"]
    require(identity["page_size"] == size, "CONFLICTING_PAGE_SIZE")
    require(identity["byte_order"] == order, "CONFLICTING_BYTE_ORDER")
    require(paths_refer_to_same_file(identity["source"], source), "SOURCE_MISMATCH")
    mapping = {number(identity["metadata_page_number"]): number(identity["metadata_physical_offset"])}
    for page in db["selected_pages"]:
        require(page["validation_status"] == "structural", "PAGE_NOT_ACCEPTED")
        require(page["page_size"] == size, "CONFLICTING_PAGE_SIZE")
        n = number(page["page_number"])
        require(n not in mapping, "AMBIGUOUS_PAGE")
        mapping[n] = number(page["physical_offset"])
    return mapping


def _read_pages(stream, offsets: dict[int, int], size: int) -> dict[int, bytes]:
    length = os.fstat(stream.fileno()).st_size
    spans = sorted(offsets.values())
    require(all(b >= a + size for a, b in zip(spans, spans[1:])), "OVERLAPPING_SOURCE_PAGES")
    data = {}
    for page, offset in offsets.items():
        require(offset + size <= length, "READ_FAILURE")
        stream.seek(offset)
        value = stream.read(size)
        require(len(value) == size, "READ_FAILURE")
        data[page] = value
    return data


def _trees(pages: dict[int, bytes], size: int, order: str, metadata: tuple[int, ...]):
    page_map = LogicalBerkeleyPageMap("export", size, order,
        [LogicalPageLocation(n, n * size, size, "export") for n in pages])
    reader = LogicalBerkeleyPageReader(page_map, logical_file_id="exact-export",
                                     range_reader=_Pages(pages, size))
    trees = {}
    for n in metadata:
        e = _metadata(pages[n], n, size, order)
        anchor = LogicalBerkeleyMetadataAnchor(reader.identity, n, size, order, e["root_page"], n * size)
        tree = LogicalBtreeMembershipResolver(anchor, reader).resolve()
        require(tree.status is ValidationStatus.STRUCTURAL, "TREE_INVALID")
        trees[n] = tree
    return page_map, trees


def _main_link(pages: dict[int, bytes], tree, size: int, order: str, target: int) -> bool:
    pairs = []
    for n in tree.leaf_page_numbers:
        extraction = BerkeleyLeafRecordExtractor(size, order, expected_page_number=n).extract(
            ValidationContext("export", n * size, pages[n]))
        pairs.extend(extraction.pairs)
    # Berkeley DB catalog page numbers are network byte order, independent of page endianness.
    return (len(pairs) == 1 and not pairs[0].key.deleted and not pairs[0].value.deleted
            and pairs[0].key.record_type == KEYDATA and pairs[0].value.record_type == KEYDATA
            and pairs[0].key.payload == b"main" and pairs[0].value.payload == target.to_bytes(4, "big"))


def validate_pages(plan: Reconstruction, pages: dict[int, bytes]) -> dict:
    size, order, sub = plan.page_size, plan.byte_order, plan.metadata_number
    require(set(pages) == set(range(len(pages))), "MISSING_PAGE")
    require(all(len(p) == size for p in pages.values()), "READ_FAILURE")
    outer = _metadata(pages[0], 0, size, order)
    wallet = _metadata(pages[sub], sub, size, order)
    require(outer["last_page_number"] == len(pages) - 1, "LAST_PAGE_MISMATCH")
    # The subdatabase field is not the global allocation high-water mark.
    require(sub <= number(wallet["last_page_number"]) <= outer["last_page_number"],
            "SUBDATABASE_LAST_PAGE_INVALID")
    require(wallet["root_page"] == plan.root, "ROOT_MISMATCH")
    require(pages[0][52:72] == pages[sub][52:72] and any(pages[0][52:72]), "DATABASE_UID_MISMATCH")
    page_map, trees = _trees(pages, size, order, (0, sub))
    require(_main_link(pages, trees[0], size, order, sub), "OUTER_RELATION_UNPROVEN")
    outer_set = set(trees[0].reachable_page_numbers)
    wallet_set = set(trees[sub].reachable_page_numbers)
    require(not outer_set.intersection(wallet_set), "SHARED_TREE_PAGES")
    require(outer_set | wallet_set | {0, sub} == set(pages), "UNACCOUNTED_PAGES")
    validated = {}
    for n, data in pages.items():
        if n in (0, sub):
            continue
        result = BerkeleyPageValidator(size, order, expected_page_number=n).validate(
            ValidationContext("export", n * size, data))
        require(result.status is ValidationStatus.STRUCTURAL, "INVALID_PAGE")
        require(result.evidence["page_type"] in (BTREE_LEAF, BTREE_INTERNAL), "UNSUPPORTED_PAGE_TYPE")
        require(not result.evidence.get("overflow_record_count"), "OVERFLOW_UNSUPPORTED")
        validated[n] = result
    for tree in trees.values():
        results = [validated[n] for n in tree.reachable_page_numbers]
        chain = BerkeleyPageChainValidator(BerkeleyAnchor(0, 0, size, order)).validate(results)
        require(not chain.reasons and chain.missing_links == 0, "PAGE_CHAIN_INVALID")
        # No links is normal for a single-page tree. Otherwise check a complete,
        # acyclic leaf chain, rather than relying on the validator's confidence label.
        leaves = set(tree.leaf_page_numbers)
        starts = [n for n in leaves if validated[n].evidence["previous_page"] == 0]
        require(len(starts) == 1, "LEAF_CHAIN_INVALID")
        seen, n = set(), starts[0]
        while n:
            require(n in leaves and n not in seen, "LEAF_CHAIN_INVALID")
            seen.add(n)
            n = validated[n].evidence["next_page"]
        require(seen == leaves, "LEAF_CHAIN_INVALID")
    for n in trees[sub].leaf_page_numbers:
        extraction = BerkeleyLeafRecordExtractor(size, order, expected_page_number=n).extract(
            ValidationContext("export", n * size, pages[n]))
        context = LogicalBerkeleyRecordPageContext(trees[sub].identity, "export", n, n * size,
                                                  size, extraction.page_status, extraction)
        for record in LogicalBitcoinWalletRecordDecoderV1().decode_context(context):
            # Preserve other wallet record types verbatim; never reinterpret them.
            require(record.state is LogicalWalletRecordState.VALID or
                    record.findings == ("record_type_unsupported",), "WALLET_RECORD_INVALID")
    recovered = LogicalBerkeleyDatabaseRecoveryPipeline(page_map, logical_file_id=plan.logical_id,
                                                      range_reader=_Pages(pages, size)).run()
    wallets = [w for w in recovered.subdatabases if w.identity.metadata_page_number == sub]
    require(len(wallets) == 1 and wallets[0].status is ValidationStatus.STRUCTURAL
            and wallets[0].membership_status is ValidationStatus.STRUCTURAL, "WALLET_INVALID")
    w = wallets[0]
    require(len(w.wallet_candidate_reports) == 1, "WALLET_CANDIDATE_AMBIGUOUS")
    actual = w.wallet_candidate_reports[0]
    require(not actual["conflicts"], "WALLET_CONFLICT")
    require(actual["record_counts"] == plan.record_counts, "RECORD_COUNTS_MISMATCH")
    require(actual["crypto_summary"] == plan.crypto_summary, "CRYPTO_COUNTS_MISMATCH")
    require(actual["crypto_summary"]["crypto_invalid_plain_records"] == 0, "CRYPTO_INVALID")
    require(w.record_pair_count == plan.record_pair_count, "RECORD_PAIR_COUNT_MISMATCH")
    return {"structural_validation_status": "BFRS_PHYSICAL_RECONSTRUCTION_VALID",
            "record_counts": actual["record_counts"], "crypto_summary": actual["crypto_summary"],
            "record_pair_count": w.record_pair_count}


def prepare(source: Path, report: dict, candidate_id: str, stream) -> Reconstruction:
    require(bool(re.fullmatch(r"legacy-wallet-[0-9a-f]{16}", candidate_id)), "INVALID_CANDIDATE_ID")
    candidates = [c for c in report["legacy_wallet_recovery"]["candidates"] if c["candidate_id"] == candidate_id]
    require(len(candidates) == 1, "CANDIDATE_NOT_UNIQUE")
    candidate = candidates[0]
    require(candidate["normalized_state"]["discovery_state"] == "ACCEPTED", "CANDIDATE_NOT_ACCEPTED")
    identities = {(p["logical_file_id"], number(p["metadata_page_number"]), number(p["root_page_number"]))
                  for p in candidate["provenance"]}
    require(len(identities) == 1, "CANDIDATE_IDENTITY_AMBIGUOUS")
    logical, sub, root = identities.pop()
    require(sub > 0, "OUTER_RELATION_UNPROVEN")
    databases = report["reconstructed_databases"]
    matches = [d for d in databases if d["identity"]["metadata_page_number"] == sub
               and d["identity"]["root_page_number"] == root
               and logical == f'reconstructed-{d["identity"]["metadata_physical_offset"]:x}-{root}']
    require(len(matches) == 1, "DATABASE_NOT_UNIQUE")
    db = matches[0]
    size, order = number(db["identity"]["page_size"]), db["identity"]["byte_order"]
    require(is_valid_page_size(size) and order in ("little", "big"), "INVALID_PAGE_GEOMETRY")
    offsets = _mapping(db, size, order, source)
    pages = _read_pages(stream, offsets, size)
    _metadata(pages[sub], sub, size, order)
    selected = []
    for outer_db in databases:
        i = outer_db["identity"]
        if i["metadata_page_number"] != 0 or i["source"] != db["identity"]["source"]:
            continue
        outer_offsets = _mapping(outer_db, size, order, source)
        outer_pages = _read_pages(stream, outer_offsets, size)
        if outer_pages[0][52:72] != pages[sub][52:72]:
            continue
        _, trees = _trees(outer_pages, size, order, (0,))
        if _main_link(outer_pages, trees[0], size, order, sub):
            selected.append((outer_offsets, outer_pages))
    require(len(selected) == 1, "OUTER_RELATION_UNPROVEN")
    outer_offsets, outer_pages = selected[0]
    require(not set(offsets).intersection(outer_offsets), "AMBIGUOUS_PAGE")
    offsets.update(outer_offsets)
    pages.update(outer_pages)
    last = number(_metadata(pages[0], 0, size, order)["last_page_number"])
    require(last + 1 == len(pages) and set(pages) == set(range(len(pages))), "MISSING_PAGE")
    # Recheck combined source spans (including catalog and wallet).
    pages = _read_pages(stream, offsets, size)
    recoveries = [w for w in report["reconstructed_wallet_results"] if w["identity"] == db["identity"]]
    require(len(recoveries) == 1, "WALLET_RECOVERY_NOT_UNIQUE")
    recovery = recoveries[0]
    require(recovery["status"] == "structural" and recovery["database_status"] == "structural", "WALLET_INCOMPLETE")
    for k in ("read_failure_page_numbers", "rejected_extraction_page_numbers"):
        require(recovery["safe_locations"][k] == [], "READ_FAILURE")
    counts = candidate["record_counts"]
    crypto = candidate["crypto_summary"]
    require(set(counts) == {"key", "ckey", "mkey", "keymeta", "defaultkey", "version", "minversion"}, "INVALID_COUNTS")
    require(set(crypto) == {"crypto_valid_plain_keys", "unique_crypto_valid_plain_keys",
                           "crypto_invalid_plain_records", "crypto_duplicate_occurrences"}, "INVALID_COUNTS")
    for v in (*counts.values(), *crypto.values()):
        number(v)
    plan = Reconstruction(pages, offsets, size, order, sub, root, logical, candidate_id,
                          counts, crypto, number(recovery["record_pair_count"]))
    validate_pages(plan, pages)
    return plan


def _publish(temp: Path, target: Path) -> None:
    # Windows rename is atomic and refuses an existing target. POSIX rename
    # overwrites: hard-link publication provides atomic no-clobber there.
    if os.name == "nt":
        os.rename(temp, target)
    else:
        os.link(temp, target)
        temp.unlink()


def export_wallet(source: Path, report_path: Path, candidate_id: str, output: Path,
                  *, allow_private_key_export: bool = False) -> dict:
    require(allow_private_key_export, "PRIVATE_KEY_EXPORT_NOT_ALLOWED")
    source, report_path, output = Path(source), Path(report_path), Path(output)
    manifest = output.with_name(output.name + ".manifest.json")
    for target in (output, manifest):
        require(not paths_refer_to_same_file(source, target) and
                not paths_refer_to_same_file(report_path, target), "PATH_COLLISION")
        require(not os.path.lexists(target), "OUTPUT_EXISTS")
    require(output.parent.is_dir(), "OUTPUT_DIRECTORY_MISSING")
    temporary = []
    try:
        report = json.loads(report_path.read_text(encoding="utf-8-sig"))
        with source.open("rb") as stream:
            plan = prepare(source, report, candidate_id, stream)
            fd, name = tempfile.mkstemp(prefix=".wallet-export-", suffix=".tmp", dir=output.parent)
            temp = Path(name)
            temporary.append(temp)
            with os.fdopen(fd, "wb") as dest:
                for n in range(len(plan.pages)):
                    dest.write(plan.pages[n])
                dest.flush()
                os.fsync(dest.fileno())
            with temp.open("rb") as generated:
                output_pages = _read_pages(generated, {n: n * plan.page_size for n in plan.pages}, plan.page_size)
            source_pages = _read_pages(stream, plan.offsets, plan.page_size)
            for n, data in source_pages.items():
                require(hashlib.sha256(data).digest() == hashlib.sha256(plan.pages[n]).digest()
                        == hashlib.sha256(output_pages[n]).digest(), "PAGE_HASH_MISMATCH")
            validation = validate_pages(plan, output_pages)
            digest = hashlib.sha256()
            for n in range(len(output_pages)):
                digest.update(output_pages[n])
            result = {**validation, "sha256": digest.hexdigest(), "size": temp.stat().st_size,
                      "page_count": len(output_pages), "page_size": plan.page_size,
                      "candidate_id": candidate_id, "source_image_basename": source.name}
            fd, name = tempfile.mkstemp(prefix=".wallet-manifest-", suffix=".tmp", dir=output.parent)
            manifest_temp = Path(name)
            temporary.append(manifest_temp)
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as dest:
                json.dump(result, dest, indent=2, sort_keys=True)
                dest.write("\n")
                dest.flush()
                os.fsync(dest.fileno())
            # Publish validated files only. A racing target is never overwritten.
            _publish(temp, output)
            try:
                _publish(manifest_temp, manifest)
            except OSError:
                raise ExportRefused("MANIFEST_PUBLICATION_FAILED_WALLET_CREATED") from None
            return result
    except ExportRefused:
        raise
    except (KeyError, TypeError, ValueError, OverflowError, IndexError):
        raise ExportRefused("INVALID_REPORT_OR_STRUCTURE") from None
    except OSError:
        raise ExportRefused("IO_OR_PUBLICATION_FAILURE") from None
    finally:
        for path in temporary:
            path.unlink(missing_ok=True)
