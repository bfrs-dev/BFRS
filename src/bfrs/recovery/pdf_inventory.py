"""Bounded PDF trailer inspection, without object resolution or decompression.

Only encryption *markers* are classified. Page contents, encryption dictionaries
referenced by object number, and xref stream payloads are deliberately not read.
The caller supplies the shared byte/read-call budget via BoundedReader.
"""
import re

MAX_SECTIONS = 32
MAX_SUBSECTIONS = 256
MAX_TOKENS = 8192
MAX_DEPTH = 32
MAX_STRING_BYTES = 65536
TAIL_BYTES = 65536
BLOCK_BYTES = 4096
SPACE = b'\x00\t\n\x0c\r '
DELIMITERS = SPACE + b'()<>[]{}/%'


class PDFMetadataLimit(ValueError):
    pass


class _Parser:
    """Small bounded PDF object lexer; strings are skipped, never retained."""

    def __init__(self, reader, offset):
        self.reader, self.pos = reader, offset
        self.block, self.start = b'', offset
        self.pending = []
        self.tokens = 0

    def byte(self):
        if self.pos >= self.reader.size:
            return b''
        if not self.start <= self.pos < self.start + len(self.block):
            self.start = self.pos
            self.block = self.reader.at(self.pos, min(BLOCK_BYTES, self.reader.size-self.pos))
        return self.block[self.pos-self.start:self.pos-self.start+1]

    def take_byte(self):
        value = self.byte()
        if not value:
            raise ValueError('PDF_TRUNCATED_METADATA')
        self.pos += 1
        return value

    def end_line(self):
        while self.byte() and self.byte() in b'\x00\t\x0c ':
            self.pos += 1
        ending = self.take_byte()
        if ending == b'\r' and self.byte() == b'\n':
            self.pos += 1
        elif ending not in (b'\r', b'\n'):
            raise ValueError('PDF_EXPECTED_LINE_END')

    def _token(self):
        self.tokens += 1
        if self.tokens > MAX_TOKENS:
            raise PDFMetadataLimit('PDF_TOKEN_LIMIT')
        while True:
            ch = self.byte()
            if not ch:
                raise ValueError('PDF_TRUNCATED_METADATA')
            if ch in SPACE:
                self.pos += 1
            elif ch == b'%':
                while self.byte() and self.byte() not in b'\r\n':
                    self.pos += 1
            else:
                break
        ch = self.take_byte()
        if ch == b'(':
            start, depth = self.pos, 1
            while depth:
                if self.pos-start >= MAX_STRING_BYTES:
                    raise PDFMetadataLimit('PDF_STRING_LIMIT')
                ch = self.take_byte()
                if ch == b'\\':
                    self.take_byte()
                elif ch == b'(':
                    depth += 1
                    if depth > MAX_DEPTH:
                        raise PDFMetadataLimit('PDF_DEPTH_LIMIT')
                elif ch == b')':
                    depth -= 1
            return ('string', None)
        if ch == b'<' and self.byte() != b'<':
            start = self.pos
            while True:
                if self.pos-start >= MAX_STRING_BYTES:
                    raise PDFMetadataLimit('PDF_STRING_LIMIT')
                ch = self.take_byte()
                if ch == b'>':
                    return ('string', None)
                if ch not in SPACE + b'0123456789abcdefABCDEF':
                    raise ValueError('PDF_INVALID_HEX_STRING')
        if ch in (b'<', b'>'):
            if self.take_byte() != ch:
                raise ValueError('PDF_INVALID_DELIMITER')
            return (ch*2, None)
        if ch in (b'[', b']'):
            return (ch, None)
        name = ch == b'/'
        word = bytearray() if name else bytearray(ch)
        while self.byte() and self.byte() not in DELIMITERS:
            if len(word) >= 256:
                raise PDFMetadataLimit('PDF_TOKEN_LENGTH_LIMIT')
            word.extend(self.take_byte())
        word = bytes(word)
        if name:
            if re.search(rb'#(?![0-9a-fA-F]{2})', word):
                raise ValueError('PDF_INVALID_NAME_ESCAPE')
            return ('name', re.sub(rb'#([0-9a-fA-F]{2})', lambda m: bytes([int(m[1], 16)]), word))
        if re.fullmatch(rb'[+-]?\d+', word):
            if len(word) > 20:
                raise PDFMetadataLimit('PDF_INTEGER_LIMIT')
            return ('int', int(word))
        if re.fullmatch(rb'[+-]?(?:\d+\.\d*|\.\d+)', word):
            return ('real', None)
        if word == b'null':
            return ('null', None)
        if word in (b'true', b'false'):
            return ('bool', word == b'true')
        return ('keyword', word)

    def peek(self, index=0):
        while len(self.pending) <= index:
            self.pending.append(self._token())
        return self.pending[index]

    def pop(self):
        return self.pending.pop(0) if self.pending else self._token()

    def object(self, depth=0):
        if depth > MAX_DEPTH:
            raise PDFMetadataLimit('PDF_DEPTH_LIMIT')
        kind, value = self.pop()
        if kind == b'<<':
            values = {}
            while self.peek()[0] != b'>>':
                key_kind, key = self.pop()
                if key_kind != 'name' or key in values:
                    raise ValueError('PDF_INVALID_OR_DUPLICATE_DICTIONARY_KEY')
                values[key] = self.object(depth+1)
            self.pop()
            return ('dict', values)
        if kind == b'[':
            values = []
            while self.peek()[0] != b']':
                values.append(self.object(depth+1))
            self.pop()
            return ('array', values)
        if kind == 'int' and self.peek()[0] == 'int' and self.peek(1) == ('keyword', b'R'):
            generation = self.pop()[1]
            self.pop()
            if value <= 0 or not 0 <= generation <= 65535:
                raise ValueError('PDF_INVALID_REFERENCE')
            return ('ref', (value, generation))
        if kind not in {'int', 'real', 'string', 'name', 'null', 'bool'}:
            raise ValueError('PDF_INVALID_OBJECT')
        return (kind, value)


def _integer(value, minimum=0):
    if value is None or value[0] != 'int' or value[1] < minimum:
        raise ValueError('PDF_INVALID_INTEGER_FIELD')
    return value[1]


def _section(reader, offset):
    if not 0 < offset < reader.size:
        raise ValueError('PDF_XREF_OFFSET_OUT_OF_RANGE')
    parser = _Parser(reader, offset)
    first = parser.pop()
    is_stream = first != ('keyword', b'xref')
    if not is_stream:
        sections = 0
        while parser.peek() != ('keyword', b'trailer'):
            sections += 1
            if sections > MAX_SUBSECTIONS:
                raise PDFMetadataLimit('PDF_XREF_SUBSECTION_LIMIT')
            _integer(parser.pop())  # first object number
            count = _integer(parser.pop(), 1)
            parser.end_line()
            start, end = parser.pos, parser.pos + count*20
            if end > reader.size:
                raise ValueError('PDF_TRUNCATED_XREF_TABLE')
            # Standard xref records have fixed width. Check boundary records and
            # seek over the rest; no complete xref table is allocated or claimed
            # to be validated. Nonstandard layouts stay UNKNOWN.
            for position in {start, end-20}:
                record = reader.at(position, 20)
                if not re.fullmatch(rb'\d{10} \d{5} [nf](?: \n|\r\n| \r)', record):
                    raise PDFMetadataLimit('PDF_XREF_RECORD_LAYOUT_UNSUPPORTED')
            parser.pos = end
        parser.pop()
    else:
        _integer(first, 1)
        if _integer(parser.pop()) > 65535 or parser.pop() != ('keyword', b'obj'):
            raise ValueError('PDF_INVALID_XREF_OBJECT')
    kind, fields = parser.object()
    if kind != 'dict':
        raise ValueError('PDF_TRAILER_DICTIONARY_MISSING')
    _integer(fields.get(b'Size'), 1)
    if b'Root' in fields and fields[b'Root'][0] != 'ref':
        raise ValueError('PDF_INVALID_ROOT_REFERENCE')
    if is_stream:
        if fields.get(b'Type') != ('name', b'XRef'):
            raise ValueError('PDF_XREF_STREAM_TYPE_MISSING')
        widths = fields.get(b'W')
        if not widths or widths[0] != 'array' or len(widths[1]) != 3:
            raise ValueError('PDF_INVALID_XREF_STREAM_WIDTHS')
        for width in widths[1]:
            _integer(width)
        length = fields.get(b'Length')
        if not length or length[0] not in ('int', 'ref'):
            raise ValueError('PDF_INVALID_STREAM_LENGTH')
        if length[0] == 'int':
            _integer(length)
        if parser.pop() != ('keyword', b'stream'):
            raise ValueError('PDF_XREF_STREAM_MISSING')
        parser.end_line()
        if length[0] == 'int' and parser.pos+length[1] > reader.size:
            raise ValueError('PDF_TRUNCATED_XREF_STREAM')
    return fields, is_stream


def inspect_pdf(reader):
    """Return metadata status; never infer a password requirement or integrity."""
    length = min(reader.size, TAIL_BYTES)
    tail = reader.at(reader.size-length, length)
    ending = re.search(rb'(?:^|[\r\n])startxref[\x00\t\n\x0c\r ]+(\d{1,20})'
                       rb'[\x00\t\n\x0c\r ]+%%EOF[\x00\t\n\x0c\r ]*\Z', tail)
    if not ending:
        raise ValueError('PDF_FINAL_STARTXREF_MISSING')
    checked = {}
    active = set()

    def visit(offset, require_stream=False):
        if offset in active:
            raise ValueError('PDF_XREF_CYCLE')
        if offset in checked:
            if require_stream and not checked[offset][1]:
                raise ValueError('PDF_HYBRID_XREF_NOT_STREAM')
            return
        if len(checked)+len(active) >= MAX_SECTIONS:
            raise PDFMetadataLimit('PDF_XREF_SECTION_LIMIT')
        active.add(offset)
        fields, is_stream = _section(reader, offset)
        if require_stream and not is_stream:
            raise ValueError('PDF_HYBRID_XREF_NOT_STREAM')
        encrypt = fields.get(b'Encrypt', ('null', None))
        if encrypt[0] not in ('ref', 'dict', 'null') or encrypt == ('dict', {}):
            raise ValueError('PDF_INVALID_ENCRYPT_ENTRY')
        for key in (b'XRefStm', b'Prev'):
            if key in fields:
                visit(_integer(fields[key], 1), require_stream=key == b'XRefStm')
        active.remove(offset)
        # Retain only the few fields needed for final classification.
        checked[offset] = (encrypt[0] != 'null', is_stream, b'Root' in fields)

    visit(int(ending[1]))
    if not any(row[2] for row in checked.values()):
        raise ValueError('PDF_ROOT_REFERENCE_MISSING')
    encrypted = any(row[0] for row in checked.values())
    return {'encryption': 'ENCRYPTED' if encrypted else 'NO_ENCRYPTION_INDICATOR',
            'structure': 'PDF_TRAILERS_CHECKED',
            'reason': 'PDF_ENCRYPT_ENTRY' if encrypted else None,
            'pdf_xref_sections': len(checked),
            'pdf_xref_streams': sum(row[1] for row in checked.values()),
            'pdf_password_required': 'NOT_CHECKED'}
