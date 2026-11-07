"""Pure byte parser for one GCC -M/-MD rule with a pilot-source-[0-8] target.

Only the producer's escaped space, tab and # syntax is decoded. Other
backslashes are literal Windows separators. LF/CRLF continuations are removed
as in classic_final_image.run.read_dependencies; no Make expansion, comments,
recipes, order-only prerequisites or additional rules are accepted.

Drive-absolute paths are normalized lexically, then deduplicated and sorted.
No existence, physical identity, dependency authority or root containment is
proved here. The caller owns admitted-byte lookup and all such checks.
"""

import ntpath
from pathlib import Path
import re


class Rejected(ValueError):
    pass


def _need(value, detail):
    if not value:
        raise Rejected('dependency-bytes: ' + detail)


def _path(token):
    _need(len(token) >= 3 and token[0] in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
          and token[1] == ':' and token[2] in '/\\' and ':' not in token[2:],
          'drive-absolute prerequisite without UNC, device namespace or stream')
    return Path(ntpath.normpath(token[0].upper() + token[1:]))


def parse(raw, *, target):
    """Return sorted unique lexical absolute Paths, without consulting the host."""
    _need(type(raw) is bytes, 'literal dependency bytes')
    _need(type(target) is str and re.fullmatch(r'pilot-source-[0-8]', target) is not None,
          'explicit pilot target')
    try:
        text = raw.decode('utf-8', errors='strict')
    except UnicodeError as error:
        raise Rejected('dependency-bytes: strict UTF-8 required') from error
    _need(all(not (ord(c) < 32 and c not in '\t\r\n') and not 127 <= ord(c) <= 159
              for c in text), 'control byte/codepoint')
    text = text.replace('\r\n', '\n')
    _need('\r' not in text, 'bare or malformed CRLF')
    last = text.rfind('\\\n')
    _need(last < 0 or bool(text[last + 2:].strip(' \t\n')), 'unfinished continuation')
    text = text.replace('\\\n', '')
    if text.endswith('\n'):
        text = text[:-1]
    _need('\n' not in text and text.startswith(target + ': '), 'one exact target rule')
    body, tokens, current, index = text[len(target) + 2:], [], [], 0
    while index < len(body):
        char = body[index]
        if char in ' \t':
            if current:
                tokens.append(''.join(current))
                current = []
        elif char == '\\':
            _need(index + 1 < len(body), 'dangling backslash')
            following = body[index + 1]
            if following in ' \t#':
                current.append(following)
                index += 1
            else:
                current.append(char)
        else:
            _need(char not in '#$;|', 'unsupported Make syntax')
            current.append(char)
        index += 1
    if current:
        tokens.append(''.join(current))
    _need(tokens, 'nonempty prerequisite inventory')
    return tuple(sorted({_path(token) for token in tokens}))
