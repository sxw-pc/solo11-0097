"""Byte-exact chunking strategies for the content-addressable archive.

Both representations are *lossless*: reassembling the manifest chunks yields
the original source bytes verbatim, including BOMs, CRLF delimiters, missing
trailing newlines and non-ASCII bytes. No JSON record is ever re-serialised;
record chunks are raw byte spans of the original file that happen to end on
record boundaries (the delimiter bytes are part of the chunk).
"""
from hashlib import sha256

FIXED_CHUNK_BYTES = 64
UTF8_BOM = b'\xef\xbb\xbf'


def chunk_hash(data: bytes) -> str:
    return sha256(data).hexdigest()


def fixed_64_chunks(data: bytes, size: int = FIXED_CHUNK_BYTES):
    """Split on fixed byte boundaries. Empty input yields one empty chunk."""
    if size <= 0:
        raise ValueError('chunk_size_must_be_positive')
    if not data:
        return [data]
    return [data[i:i + size] for i in range(0, len(data), size)]


def record_chunks(data: bytes):
    """Split a JSONL byte stream into raw record spans plus a prefix.

    Each record chunk includes its *original* delimiter bytes (``\\n`` or
    ``\\r\\n``); a final record without a trailing newline is tagged
    ``unterminated`` in the manifest so reassembly stays byte-exact. A UTF-8
    BOM and any blank lines preceding the first record are kept verbatim in a
    prefix span instead of being silently decoded away.
    """
    prefix = b''
    rest = data
    if rest.startswith(UTF8_BOM):
        prefix += UTF8_BOM
        rest = rest[len(UTF8_BOM):]
    # Leading blank lines (e.g. "\n", "\r\n", "\n\n") belong to no record.
    while True:
        nl = rest.find(b'\n')
        if nl == -1:
            break
        line = rest[:nl + 1]
        if line.strip():
            break
        prefix += line
        rest = rest[nl + 1:]

    chunks = []
    while rest:
        nl = rest.find(b'\n')
        if nl == -1:
            chunks.append((rest, {'terminated': False}))
            break
        chunks.append((rest[:nl + 1], {'terminated': True,
                                       'crlf': rest[:nl + 1].endswith(b'\r\n')}))
        rest = rest[nl + 1:]
    return prefix, chunks


def build_manifest_fixed_64(data: bytes):
    chunks = fixed_64_chunks(data)
    return {
        'representation': 'fixed_64',
        'chunk_size': FIXED_CHUNK_BYTES,
        'byte_length': len(data),
        'chunks': [{'hash': chunk_hash(c), 'length': len(c)} for c in chunks],
    }


def build_manifest_record_chunks(data: bytes):
    prefix, chunks = record_chunks(data)
    has_bom = data.startswith(UTF8_BOM)
    return {
        'representation': 'record_chunks',
        'record_encoding': 'utf-8-jsonl-preserve-delimiters',
        'byte_length': len(data),
        'has_bom': has_bom,
        'prefix_hash': chunk_hash(prefix) if prefix else None,
        'prefix_length': len(prefix),
        'chunks': [{'hash': chunk_hash(span), 'length': len(span), **meta}
                   for span, meta in chunks],
    }


def build_manifest(data: bytes, representation: str):
    if representation == 'fixed_64':
        return build_manifest_fixed_64(data)
    if representation == 'record_chunks':
        return build_manifest_record_chunks(data)
    raise ValueError(f'unknown_representation:{representation}')


def manifest_chunk_hashes(manifest: dict):
    hashes = [c['hash'] for c in manifest['chunks']]
    if manifest['representation'] == 'record_chunks' and manifest.get('prefix_hash'):
        hashes.append(manifest['prefix_hash'])
    return hashes


def reassemble(manifest: dict, chunk_loader) -> bytes:
    """Rebuild the exact source bytes. ``chunk_loader(hash) -> bytes``."""
    rep = manifest['representation']
    if rep == 'fixed_64':
        out = b''.join(chunk_loader(c['hash']) for c in manifest['chunks'])
    elif rep == 'record_chunks':
        parts = []
        if manifest.get('prefix_hash'):
            parts.append(chunk_loader(manifest['prefix_hash']))
        for c in manifest['chunks']:
            span = chunk_loader(c['hash'])
            if not c.get('terminated', True) and span.endswith(b'\n'):
                raise ValueError('unterminated_chunk_must_not_carry_newline')
            parts.append(span)
        out = b''.join(parts)
    else:
        raise ValueError(f'unknown_representation:{rep}')
    if len(out) != manifest['byte_length']:
        raise ValueError('reassembled_length_mismatch')
    return out
