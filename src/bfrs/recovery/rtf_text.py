"""Bounded RTF text reader; never executes fields or decodes embedded objects.

Supports WordPad-style groups, code pages, hex escapes and Unicode fallback.
Unsupported encodings/alternate Unicode destinations fail explicitly.
"""
from dataclasses import dataclass, replace
from io import StringIO
import re

MAX_RTF_BYTES = 16 * 1024 * 1024
MAX_RTF_TEXT_BYTES = 4 * 1024 * 1024
MAX_RTF_DEPTH = 256
_CONTROL = re.compile(rb'([A-Za-z]{1,32})(-?[0-9]{1,10})? ?')
_TEXT = re.compile(rb'[^\\{}\r\n]+')
_SKIP = frozenset({
    'fonttbl', 'colortbl', 'stylesheet', 'info', 'pict', 'object', 'objdata',
    'datastore', 'themedata', 'colorschememapping', 'listtable',
    'listoverridetable', 'revtbl', 'rsidtbl', 'generator', 'filetbl',
    'fldinst', 'nonshppict', 'shppict', 'xmlnstbl',
})
_CHARSETS = {0: None, 1: None, 2: 'unsupported', 77: 'mac_roman',
    128: 'cp932', 129: 'cp949', 130: 'cp1361', 134: 'cp936', 136: 'cp950',
    161: 'cp1253', 162: 'cp1254', 163: 'cp1258', 177: 'cp1255',
    178: 'cp1256', 186: 'cp1257', 204: 'cp1251', 222: 'cp874',
    238: 'cp1250', 254: 'cp437', 255: 'cp850'}
_SPECIAL = {'par': '\n', 'line': '\n', 'tab': '\t', 'cell': '\t',
    'row': '\n', 'page': '\n', 'sect': '\n', 'emdash': '\u2014',
    'endash': '\u2013', 'bullet': '\u2022', 'lquote': '\u2018',
    'rquote': '\u2019', 'ldblquote': '\u201c', 'rdblquote': '\u201d'}


class RTFError(ValueError):
    pass


@dataclass
class _State:
    skip: bool = False
    font_table: bool = False
    uc: int = 1
    codepage: str = 'cp1252'
    font: int | None = None


def extract_rtf(data: bytes) -> bytes:
    if len(data) > MAX_RTF_BYTES:
        raise RTFError('RTF_FILE_LIMIT')
    if not re.match(rb'^\{\\rtf1(?:[^0-9]|$)', data):
        raise RTFError('RTF_FORMAT_UNCONFIRMED')
    state = _State()
    stack = []
    fonts = {}
    default_font = None
    pending = bytearray()
    output = StringIO()
    text_size = 0
    high_surrogate = None
    fallback = 0
    closed = False

    def emit(text):
        nonlocal text_size, high_surrogate
        if not text:
            return
        if high_surrogate is not None:
            if 0xDC00 <= ord(text[0]) <= 0xDFFF:
                text = chr(0x10000 + ((high_surrogate - 0xD800) << 10)
                           + ord(text[0]) - 0xDC00) + text[1:]
                high_surrogate = None
            else:
                raise RTFError('RTF_INVALID_UNICODE')
        if 0xD800 <= ord(text[-1]) <= 0xDBFF:
            high_surrogate = ord(text[-1])
            text = text[:-1]
        try:
            text_size += len(text.encode('utf-8'))
        except UnicodeError as error:
            raise RTFError('RTF_INVALID_UNICODE') from error
        if text_size > MAX_RTF_TEXT_BYTES:
            raise RTFError('RTF_TEXT_LIMIT')
        output.write(text)

    def flush():
        if not pending:
            return
        encoding = fonts.get(state.font) or state.codepage
        try:
            emit(pending.decode(encoding, 'strict'))
        except (LookupError, UnicodeError) as error:
            raise RTFError('RTF_ENCODING_UNSUPPORTED_OR_INVALID') from error
        pending.clear()

    def byte_text(value):
        nonlocal fallback
        count = min(fallback, len(value))
        fallback -= count
        if not state.skip:
            pending.extend(value[count:])
            if len(pending) > MAX_RTF_TEXT_BYTES:
                raise RTFError('RTF_TEXT_LIMIT')

    i = 0
    while i < len(data):
        byte = data[i]
        if closed:
            if data[i:].strip(b'\r\n\t ') :
                raise RTFError('RTF_TRAILING_DATA')
            break
        if byte in (123, 125):
            flush()
            fallback = 0
            if byte == 123:
                if len(stack) >= MAX_RTF_DEPTH:
                    raise RTFError('RTF_DEPTH_LIMIT')
                stack.append(replace(state))
            else:
                if not stack:
                    raise RTFError('RTF_UNBALANCED_GROUP')
                state = stack.pop()
                closed = not stack
            i += 1
            continue
        if byte in (10, 13):
            i += 1
            continue
        if byte != 92:
            match = _TEXT.match(data, i)
            byte_text(match.group())
            i = match.end()
            continue
        i += 1
        if i == len(data):
            raise RTFError('RTF_TRUNCATED_CONTROL')
        symbol = data[i]
        if symbol == 39:
            pair = data[i+1:i+3]
            if len(pair) != 2 or not re.fullmatch(rb'[0-9A-Fa-f]{2}', pair):
                raise RTFError('RTF_INVALID_HEX')
            byte_text(bytes([int(pair, 16)]))
            i += 3
            continue
        if not (65 <= symbol <= 90 or 97 <= symbol <= 122):
            i += 1
            if symbol in (92, 123, 125):
                byte_text(bytes([symbol]))
            elif symbol == 42:
                flush()
                state.skip = True
            elif symbol in (126, 95, 45):
                if fallback:
                    fallback -= 1
                elif not state.skip:
                    flush()
                    emit({126: '\u00a0', 95: '\u2011', 45: '\u00ad'}[symbol])
            continue
        match = _CONTROL.match(data, i)
        word = match[1].decode('ascii')
        number = int(match[2]) if match[2] is not None else None
        i = match.end()
        if i < len(data) and not match.group().endswith(b' '):
            if ((number is None and (65 <= data[i] <= 90 or 97 <= data[i] <= 122))
                    or (number is not None and 48 <= data[i] <= 57)):
                raise RTFError('RTF_CONTROL_LIMIT')
        if word == 'bin':
            if number is None or number < 0 or number > len(data) - i:
                raise RTFError('RTF_INVALID_BINARY_LENGTH')
            i += number
            if fallback:
                fallback -= 1
            elif not state.skip:
                flush()
                emit('\n')
            continue
        if fallback:
            fallback -= 1
            continue
        if word in _SKIP:
            flush()
            if not state.skip:
                emit('\n')
            state.skip = True
            state.font_table = state.font_table or word == 'fonttbl'
        elif word == 'deff' and number is not None:
            default_font = number
            state.font = number
        elif word == 'f' and number is not None:
            flush()
            state.font = number
        elif word == 'fcharset' and state.font_table and number is not None:
            fonts[state.font] = _CHARSETS.get(number, 'unsupported')
        elif word == 'cpg' and state.font_table and number is not None:
            fonts[state.font] = 'cp' + str(number)
        elif state.skip:
            continue
        elif word in {'upr', 'ud'}:
            raise RTFError('RTF_ALTERNATE_UNICODE_UNSUPPORTED')
        elif word in {'ansi', 'mac', 'pc', 'pca', 'ansicpg'}:
            flush()
            state.codepage = ('cp' + str(number) if word == 'ansicpg' else
                             {'ansi':'cp1252', 'mac':'mac_roman', 'pc':'cp437', 'pca':'cp850'}[word])
        elif word == 'plain':
            flush()
            state.font = default_font
        elif word == 'uc':
            if number is None or not 0 <= number <= 255:
                raise RTFError('RTF_INVALID_UNICODE_FALLBACK')
            state.uc = number
        elif word == 'u':
            if number is None or not -32768 <= number <= 65535:
                raise RTFError('RTF_INVALID_UNICODE')
            flush()
            emit(chr(number & 0xffff))
            fallback = state.uc
        elif word in _SPECIAL:
            flush()
            emit(_SPECIAL[word])
    flush()
    if stack or not closed:
        raise RTFError('RTF_UNBALANCED_GROUP')
    if high_surrogate is not None:
        raise RTFError('RTF_INVALID_UNICODE')
    return output.getvalue().encode('utf-8')
