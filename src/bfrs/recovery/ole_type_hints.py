"""Directory-only OLE hints: never an encryption or payload classification."""

OLE_HINT_REVISION = 1
PPT_CLSID = '64818D10-4F9B-11CF-86EA-00AA00B929E8'
INSTALLER_TYPES = {
    '000C1084-0000-0000-C000-000000000046': 'WINDOWS_INSTALLER_DATABASE',
    '000C1082-0000-0000-C000-000000000046': 'WINDOWS_INSTALLER_TRANSFORM',
    '000C1086-0000-0000-C000-000000000046': 'WINDOWS_INSTALLER_PATCH',
}


def ole_type_hint(row):
    entries = row.get('ole_directory_entries', [])
    names = {e['name'] for e in entries if e.get('type') == 2}
    clsid = (row.get('ole_root_clsid') or '').upper()
    kind, evidence = 'UNDETERMINED', []
    if row.get('ole_directory_warnings'):
        evidence = ['DIRECTORY_WARNINGS']
    elif clsid == PPT_CLSID or names & {'PowerPoint Document', 'Current User'}:
        kind = 'POWERPOINT_BINARY'
        evidence = sorted(names & {'PowerPoint Document', 'Current User'})
        if clsid == PPT_CLSID:
            evidence.append('ROOT_CLSID:' + clsid)
    elif clsid in INSTALLER_TYPES:
        kind, evidence = INSTALLER_TYPES[clsid], ['ROOT_CLSID:' + clsid]
    elif 'PP40' in names:
        kind, evidence = 'POWERPOINT_LEGACY_POSSIBLE', ['PP40']
    elif any('WilcomDesignInformation' in n for n in names):
        kind = 'EMBROIDERY_DESIGN_POSSIBLE'
        evidence = sorted(n for n in names if 'WilcomDesignInformation' in n)
    elif names & {'Stitches', 'SStitches', 'NewEmbroidery'}:
        kind = 'EMBROIDERY_DESIGN_POSSIBLE'
        evidence = sorted(names & {'Stitches', 'SStitches', 'NewEmbroidery'})
    elif ('Catalog' in names and any(n.isascii() and n.isdigit() for n in names)
          and all(n == 'Catalog' or (n.isascii() and n.isdigit()) for n in names)):
        kind, evidence = 'THUMBNAIL_CACHE_POSSIBLE', ['Catalog', 'NUMERIC_STREAM_NAMES']
    elif names & {'TravelLog', 'FrameList'}:
        kind = 'BROWSER_STATE_POSSIBLE'
        evidence = sorted(names & {'TravelLog', 'FrameList'})
    elif 'VGCoreDataStream' in names:
        kind, evidence = 'GRAPHICS_DOCUMENT_POSSIBLE', ['VGCoreDataStream']
    elif row.get('ole_directory_entry_count') == 0:
        kind, evidence = 'EMPTY_DIRECTORY', ['NO_DIRECTORY_ENTRIES']
    return dict(ole_type_hint=kind, ole_type_hint_evidence=evidence[:4],
                ole_type_hint_scope='DIRECTORY_HINT_NOT_ENCRYPTION_OR_PAYLOAD_VALIDATION',
                ole_type_hint_partial=bool(row.get('ole_directory_entries_truncated')),
                ole_type_hint_revision=OLE_HINT_REVISION)


def ppt_candidate(row):
    """Conservative refresh of old cached OLE directories; names may be partial."""
    return ((row.get('ole_root_clsid') or '').upper() == PPT_CLSID
            or any(e.get('name') in {'PowerPoint Document', 'Current User'}
                   for e in row.get('ole_directory_entries', [])))
