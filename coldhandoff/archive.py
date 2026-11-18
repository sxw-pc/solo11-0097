"""Content-addressable, byte-exact archive for cold-chain source files.

Storage model
-------------
* Chunks live in an immutable on-disk content-addressable store
  (``cas-objects/xx/<sha256>``); identical bytes exist on disk exactly once,
  writes are temp-file + atomic rename and existing objects are never mutated.
* Per-source ordered manifests, pointer generations, reader pins and GC
  ledgers live in SQLite (see :mod:`coldhandoff.store`). A manifest row is
  immutable once published; re-publication appends a new generation.
* Readers pin the latest published generation for the duration of a read and
  only observe manifests published at or below that generation. GC never
  removes a chunk reachable from a published manifest an active pin can see.

Migration is crash-safe at every step: staged manifests resume from the still
present raw BLOB, the pointer only switches after a reassembled SHA-256 match,
and the old BLOB is reclaimed only after the switched manifest is verified.
"""
import fcntl
import hashlib
import json
import os
import tempfile
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .chunking import (
    build_manifest,
    chunk_hash,
    manifest_chunk_hashes,
    reassemble,
)
from .store import connect


class ArchiveError(RuntimeError):
    pass


class RecoveryError(ArchiveError):
    pass


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _canonical(manifest: dict) -> str:
    return json.dumps(manifest, sort_keys=True, ensure_ascii=False,
                      separators=(',', ':')).encode('utf-8').decode('utf-8')


# --------------------------------------------------------------------------- #
# Filesystem content-addressable chunk store
# --------------------------------------------------------------------------- #
class ContentStore:
    """Immutable, deduplicated on-disk blob store keyed by SHA-256."""

    def __init__(self, root: Path):
        self.root = Path(root)

    @classmethod
    def for_db(cls, db_path) -> 'ContentStore':
        # Resolve to an absolute anchor: relative db paths otherwise resolve
        # against whatever working directory each connection happens to use.
        return cls(Path(db_path).resolve().parent / 'cas-objects')

    def _paths(self, digest: str):
        shard = self.root / digest[:2]
        return shard, shard / digest[2:]

    def path(self, digest: str) -> Path:
        return self._paths(digest)[1]

    def exists(self, digest: str) -> bool:
        return self._paths(digest)[1].is_file()

    def put(self, data: bytes) -> str:
        digest = _sha256(data)
        shard, final = self._paths(digest)
        if final.is_file():
            return digest
        shard.mkdir(parents=True, exist_ok=True)
        # Atomic, crash-safe injection: a partial temp file is never visible
        # under its content hash and is swept by recovery/GC.
        fd, tmp = tempfile.mkstemp(prefix='.' + digest[2:] + '.tmp-',
                                   dir=str(shard))
        try:
            with os.fdopen(fd, 'wb') as fh:
                fh.write(data)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, final)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
        return digest

    def get(self, digest: str) -> bytes:
        _, final = self._paths(digest)
        try:
            return final.read_bytes()
        except FileNotFoundError:
            raise ArchiveError(f'chunk_missing:{digest}')

    def remove(self, digest: str) -> bool:
        _, final = self._paths(digest)
        try:
            final.unlink()
            return True
        except FileNotFoundError:
            return False

    def iter_objects(self):
        if not self.root.is_dir():
            return
        for shard in sorted(self.root.iterdir()):
            if not shard.is_dir() or len(shard.name) != 2:
                continue
            for obj in sorted(shard.iterdir()):
                # Full digest = 2-char shard + 62-char object file name.
                if obj.is_file() and len(obj.name) == 62:
                    yield obj

    def iter_temp_files(self):
        if not self.root.is_dir():
            return
        for shard in sorted(self.root.iterdir()):
            if not shard.is_dir():
                continue
            for obj in sorted(shard.iterdir()):
                if obj.is_file() and '.tmp-' in obj.name:
                    yield obj

    def physical_accounting(self) -> dict:
        files = list(self.iter_objects())
        return {
            'physical_chunk_files': len(files),
            'physical_chunk_bytes': sum(f.stat().st_size for f in files),
        }

    def ensure(self) -> 'ContentStore':
        self.root.mkdir(parents=True, exist_ok=True)
        return self


# --------------------------------------------------------------------------- #
# Fault injection
# --------------------------------------------------------------------------- #
@dataclass
class FaultPlan:
    """Crash points used by the migration failure tests."""
    fail_at: str = None              # mid_chunk|before_publish|after_switch|after_reclaim
    chunks_before_fail: int = 1


# --------------------------------------------------------------------------- #
# Cross-connection coordination locks
# --------------------------------------------------------------------------- #
@contextmanager
def _cas_lock(db_path, exclusive: bool):
    """Filesystem lock serialising chunk injection against GC deletion.

    Migrations take a *shared* lock (they may run concurrently and their
    content-addressed writes are idempotent); GC takes the *exclusive* lock so
    it can never delete a chunk an in-flight migration has injected but not
    yet protected with a published manifest. SQLite locks only cover row
    transactions, not the surrounding filesystem chunk store, so this lock
    file closes that gap.
    """
    lock_path = Path(db_path).resolve().parent / 'cas-objects' / '.cas.lock'
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    fh = open(lock_path, 'a+')
    try:
        fcntl.flock(fh.fileno(),
                    fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
        yield
    finally:
        fcntl.flock(fh.fileno(), fcntl.LOCK_UN)
        fh.close()


@contextmanager
def migration_lock(db_path):
    with _cas_lock(db_path, exclusive=False):
        yield


@contextmanager
def gc_lock(db_path):
    with _cas_lock(db_path, exclusive=True):
        yield


# --------------------------------------------------------------------------- #
# Reader views: pin a generation for the whole read
# --------------------------------------------------------------------------- #
class ReaderView:
    """Pins one published generation; reads are stable until released."""

    def __init__(self, db, store: ContentStore, hold_seconds: float = 30, now: float = None):
        self.db = db
        now = time.time() if now is None else now
        row = db.execute(
            "SELECT COALESCE(MAX(source_gen),0) AS g FROM cas_manifest "
            "WHERE status='published'").fetchone()
        self.generation = row['g']
        self.pin_id = 'pin-' + uuid.uuid4().hex
        db.execute(
            'INSERT INTO cas_pin(pin_id,generation,created_at,expires_at) '
            'VALUES(?,?,?,?)',
            (self.pin_id, self.generation, now, now + hold_seconds))
        db.commit()
        self.store = store

    def source_bytes(self, source_id: int) -> bytes:
        return _read_source_bytes(self.db, self.store, source_id,
                                  pinned_generation=self.generation)

    def release(self):
        self.db.execute('DELETE FROM cas_pin WHERE pin_id=?', (self.pin_id,))
        self.db.commit()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.release()


@contextmanager
def open_reader(db_path, hold_seconds: float = 30, now: float = None):
    db = connect(db_path)
    store = ContentStore.for_db(db_path)
    view = ReaderView(db, store, hold_seconds=hold_seconds, now=now)
    try:
        yield view
    finally:
        view.release()
        db.close()


def _read_source_bytes(db, store: ContentStore, source_id: int,
                       pinned_generation: int = None) -> bytes:
    """Single read path for both raw-BLOB and archived sources.

    Manifest selection order:

    1. A published manifest at or below the reader's pinned generation, when
       one exists (the stable snapshot the reader opened).
    2. Otherwise the current pointer manifest (newer than the pin). Its chunks
       are protected for as long as the pointer references them, and the final
       SHA-256 check proves the bytes are still the original source.
    3. Otherwise the coexisting raw BLOB (pre-migration sources).

    Every path re-verifies the result against ``source_file.hash`` so corrupt
    or missing chunks can never masquerade as evidence.
    """
    src = db.execute(
        'SELECT id,hash,raw FROM source_file WHERE id=?', (source_id,)
    ).fetchone()
    if src is None:
        raise KeyError(f'unknown_source:{source_id}')
    manifest_row = None
    if pinned_generation is not None:
        manifest_row = db.execute(
            "SELECT * FROM cas_manifest WHERE source_id=? AND status='published' "
            "AND source_gen<=? ORDER BY source_gen DESC LIMIT 1",
            (source_id, pinned_generation)).fetchone()
    if manifest_row is None:
        pointer = db.execute(
            'SELECT manifest_id FROM cas_pointer WHERE source_id=?',
            (source_id,)).fetchone()
        if pointer is not None:
            manifest_row = db.execute(
                'SELECT * FROM cas_manifest WHERE manifest_id=?',
                (pointer['manifest_id'],)).fetchone()

    if manifest_row is not None:
        manifest = json.loads(manifest_row['manifest_json'])
        data = reassemble(manifest, store.get)
    else:
        data = bytes(src['raw'])

    if _sha256(data) != src['hash']:
        raise ArchiveError(
            f'source_hash_mismatch:{source_id}:{src["hash"]}')
    return data


def read_source_bytes(db_path, source_id: int) -> bytes:
    """Ad-hoc byte-exact read without holding a long-lived pin."""
    db = connect(db_path)
    try:
        store = ContentStore.for_db(db_path)
        return _read_source_bytes(db, store, source_id)
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Manifest publication (atomic compare-and-swap on the source pointer)
# --------------------------------------------------------------------------- #
def _next_generation(db) -> int:
    db.execute(
        'INSERT INTO cas_generation(generation) '
        'SELECT COALESCE(MAX(generation),0)+1 FROM cas_generation')
    return db.execute('SELECT MAX(generation) AS g FROM cas_generation').fetchone()['g']


def _publish(db, manifest_id: int, now: float) -> int:
    """Move staged -> published and CAS-switch the pointer in one txn.

    Idempotent under concurrency: if another connection already published
    this exact manifest, adopt its generation instead of failing.
    """
    db.execute('BEGIN IMMEDIATE')
    try:
        staged = db.execute(
            'SELECT * FROM cas_manifest WHERE manifest_id=?',
            (manifest_id,)).fetchone()
        if staged is None:
            raise ArchiveError(f'manifest_missing:{manifest_id}')
        if staged['status'] == 'published':
            # Another worker won the race; ensure the pointer still names the
            # newest published manifest for this source, then adopt its gen.
            db.execute(
                'INSERT INTO cas_pointer(source_id,representation,manifest_id,'
                'source_gen,switched_at,blob_reclaimed) VALUES(?,?,?,?,?,0) '
                'ON CONFLICT(source_id) DO UPDATE SET '
                'representation=excluded.representation,'
                'manifest_id=excluded.manifest_id,'
                'source_gen=excluded.source_gen,'
                'switched_at=excluded.switched_at '
                'WHERE cas_pointer.source_gen < excluded.source_gen',
                (staged['source_id'], staged['representation'], manifest_id,
                 staged['source_gen'], now))
            db.execute('COMMIT')
            return staged['source_gen']
        if staged['status'] != 'staged':
            raise ArchiveError(f'manifest_not_staged:{manifest_id}')
        generation = _next_generation(db)
        db.execute(
            'UPDATE cas_manifest SET status=?, source_gen=?, published_at=? '
            'WHERE manifest_id=?',
            ('published', generation, now, manifest_id))
        db.execute(
            'INSERT INTO cas_pointer(source_id,representation,manifest_id,'
            'source_gen,switched_at,blob_reclaimed) VALUES(?,?,?,?,?,0) '
            'ON CONFLICT(source_id) DO UPDATE SET '
            'representation=excluded.representation,'
            'manifest_id=excluded.manifest_id,'
            'source_gen=excluded.source_gen,'
            'switched_at=excluded.switched_at '
            'WHERE cas_pointer.source_gen < excluded.source_gen',
            (staged['source_id'], staged['representation'], manifest_id,
             generation, now))
        db.execute('COMMIT')
        return generation
    except BaseException:
        db.execute('ROLLBACK')
        raise


def _chunk_blobs(data: bytes, representation: str):
    """Return (manifest, [(hash, bytes), ...]) covering every stored span."""
    manifest = build_manifest(data, representation)
    blobs = []
    if representation == 'fixed_64':
        from .chunking import fixed_64_chunks
        for span in fixed_64_chunks(data):
            blobs.append((chunk_hash(span), span))
    elif representation == 'record_chunks':
        from .chunking import record_chunks
        prefix, chunks = record_chunks(data)
        if prefix:
            blobs.append((chunk_hash(prefix), prefix))
        for span, _meta in chunks:
            blobs.append((chunk_hash(span), span))
    else:
        raise ValueError(f'unknown_representation:{representation}')
    return manifest, blobs


# --------------------------------------------------------------------------- #
# Online migration
# --------------------------------------------------------------------------- #
def migrate_source(db_path, source_id: int, representation: str, *,
                   faults: FaultPlan = None, now: float = None,
                   reclaim: bool = True) -> dict:
    """Archive one source. Idempotent and safe to resume after any crash.

    ``reclaim=False`` leaves the old raw BLOB in place after the pointer
    switch, exposing the coexistence state; a later :func:`run_gc`,
    :func:`recover` or another call reclaims it once the manifest verifies.
    """
    now = time.time() if now is None else now
    faults = faults or FaultPlan()
    store = ContentStore.for_db(db_path).ensure()
    # Hold the shared migration lock across chunk injection, verification and
    # publication so an exclusive GC cannot delete an unprotected chunk.
    with migration_lock(db_path):
        db = connect(db_path)
        try:
            src = db.execute(
                'SELECT id,name,hash,raw FROM source_file WHERE id=?',
                (source_id,)).fetchone()
            if src is None:
                raise KeyError(f'unknown_source:{source_id}')
            data = bytes(src['raw'])
            pointer = db.execute(
                'SELECT * FROM cas_pointer WHERE source_id=?',
                (source_id,)).fetchone()
            if not data and pointer is not None:
                # Raw BLOB already reclaimed: the verified published manifest is
                # now the only durable copy, read it back through the read path.
                data = _read_source_bytes(db, store, source_id)
            elif not data and src['hash'] != _sha256(b''):
                raise RecoveryError(
                    f'no_recoverable_copy:{source_id}')
            # An empty BLOB is itself a valid zero-byte source; keep it as data.
            if _sha256(data) != src['hash']:
                raise ArchiveError(f'raw_blob_corrupt:{source_id}')

            manifest, blobs = _chunk_blobs(data, representation)
            canonical = _canonical(manifest)
            manifest_id = _sha256(
                f'{source_id}|{representation}|{src["hash"]}|{canonical}'.encode())

            # Idempotent: the exact layout was published before, possibly under an
            # earlier pointer (e.g. representation switching back and forth).
            existing = db.execute(
                'SELECT * FROM cas_manifest WHERE manifest_id=?',
                (manifest_id,)).fetchone()
            if existing is not None and existing['status'] == 'published':
                if _sha256(reassemble(manifest, store.get)) != src['hash']:
                    raise ArchiveError(
                        f'existing_manifest_unverifiable:{manifest_id}')
                generation = _publish(db, manifest_id, now)
                reclaimed = _reclaim_blob(db, store, source_id, now) \
                    if reclaim else bool(pointer and pointer['blob_reclaimed'])
                return {
                    'source_id': source_id, 'name': src['name'],
                    'source_hash': src['hash'], 'representation': representation,
                    'manifest_id': manifest_id, 'generation': generation,
                    'byte_length': len(data), 'chunk_refs': len(blobs),
                    'blob_reclaimed': reclaimed, 'idempotent': True,
                }

            staged = db.execute(
                'SELECT * FROM cas_manifest WHERE source_id=? AND representation=? '
                "AND status='staged' ORDER BY rowid DESC",
                (source_id, representation)).fetchone()
            if staged is not None and staged['manifest_id'] != manifest_id:
                # A stale attempt for a different byte layout: abort it, restart.
                db.execute(
                    'UPDATE cas_manifest SET status=?, aborted_at=? WHERE manifest_id=?',
                    ('aborted', now, staged['manifest_id']))
                db.commit()
                staged = None
            if staged is None:
                # OR IGNORE absorbs a concurrent worker inserting the identical
                # (content-addressed) manifest; re-read whichever row won.
                db.execute(
                    'INSERT OR IGNORE INTO cas_manifest(manifest_id,source_id,'
                    'representation,source_gen,source_hash,byte_length,status,'
                    'manifest_json,created_at) VALUES(?,?,?,?,?,?,?,?,?)',
                    (manifest_id, source_id, representation, 0, src['hash'],
                     len(data), 'staged', canonical, now))
                db.commit()
                staged = db.execute(
                    'SELECT * FROM cas_manifest WHERE manifest_id=?',
                    (manifest_id,)).fetchone()
                if staged is not None and staged['status'] == 'published':
                    # A concurrent worker fully published it while we were staging.
                    generation = _publish(db, manifest_id, now)
                    reclaimed = _reclaim_blob(db, store, source_id, now) \
                        if reclaim else bool(pointer and pointer['blob_reclaimed'])
                    return {
                        'source_id': source_id, 'name': src['name'],
                        'source_hash': src['hash'], 'representation': representation,
                        'manifest_id': manifest_id, 'generation': generation,
                        'byte_length': len(data), 'chunk_refs': len(blobs),
                        'blob_reclaimed': reclaimed, 'idempotent': True,
                    }

            # Inject chunks; ContentStore.put is idempotent so resumed runs and
            # chunks shared with other sources cost nothing on the second write.
            for index, (digest, span) in enumerate(blobs):
                if not store.exists(digest):
                    if faults.fail_at == 'mid_chunk' \
                            and index >= faults.chunks_before_fail:
                        raise ArchiveError('injected_fault:mid_chunk')
                    store.put(span)

            # Do not publish until the full immutable copy reassembles to the
            # exact original SHA-256.
            rebuilt = reassemble(manifest, store.get)
            if _sha256(rebuilt) != src['hash']:
                raise ArchiveError(f'reassembly_hash_mismatch:{source_id}')

            if faults.fail_at == 'before_publish':
                raise ArchiveError('injected_fault:before_publish')

            generation = _publish(db, manifest_id, now)

            if faults.fail_at == 'after_switch':
                raise ArchiveError('injected_fault:after_switch')

            reclaimed = _reclaim_blob(db, store, source_id, now) if reclaim else False

            if faults.fail_at == 'after_reclaim':
                raise ArchiveError('injected_fault:after_reclaim')

            return {
                'source_id': source_id,
                'name': src['name'],
                'source_hash': src['hash'],
                'representation': representation,
                'manifest_id': manifest_id,
                'generation': generation,
                'byte_length': len(data),
                'chunk_refs': len(blobs),
                'blob_reclaimed': reclaimed,
            }
        finally:
            db.close()


def migrate_all(db_path, representation: str, *, faults: FaultPlan = None,
                now: float = None, reclaim: bool = True) -> list:
    db = connect(db_path)
    try:
        ids = [r['id'] for r in db.execute(
            'SELECT id FROM source_file ORDER BY id')]
    finally:
        db.close()
    return [migrate_source(db_path, sid, representation,
                           faults=faults, now=now, reclaim=reclaim)
            for sid in ids]


def _reclaim_blob(db, store: ContentStore, source_id: int, now: float) -> bool:
    """Drop the old BLOB only while the switched manifest verifies."""
    pointer = db.execute(
        'SELECT * FROM cas_pointer WHERE source_id=?', (source_id,)
    ).fetchone()
    if pointer is None or pointer['blob_reclaimed']:
        return bool(pointer and pointer['blob_reclaimed'])
    manifest_row = db.execute(
        'SELECT * FROM cas_manifest WHERE manifest_id=?',
        (pointer['manifest_id'],)).fetchone()
    manifest = json.loads(manifest_row['manifest_json'])
    src = db.execute('SELECT hash FROM source_file WHERE id=?',
                     (source_id,)).fetchone()
    rebuilt = reassemble(manifest, store.get)
    if _sha256(rebuilt) != src['hash']:
        raise ArchiveError(f'unsafe_reclaim:{source_id}')
    with db:
        db.execute("UPDATE source_file SET raw=X'' WHERE id=?", (source_id,))
        db.execute(
            'UPDATE cas_pointer SET blob_reclaimed=1 WHERE source_id=?',
            (source_id,))
    return True


# --------------------------------------------------------------------------- #
# Crash recovery
# --------------------------------------------------------------------------- #
def recover(db_path, *, grace_seconds: float = 60, now: float = None) -> dict:
    """Resume/interrupt-proof startup reconciliation.

    Guarantees afterwards: every switched source has at least one complete,
    hash-verified manifest copy; every staged attempt is either published or
    aborted; no BLOB is reclaimed behind an unverifiable manifest.
    """
    now = time.time() if now is None else now
    store = ContentStore.for_db(db_path)
    # Recovery resumes injections and reclaims BLOBs: take the same exclusive
    # coordination lock as GC so it cannot race a running migration.
    with gc_lock(db_path):
        swept_tmp = 0
        if store.root.is_dir():
            for tmp in list(store.iter_temp_files()):
                if now - tmp.stat().st_mtime >= grace_seconds:
                    tmp.unlink()
                    swept_tmp += 1

        db = connect(db_path)
        resumed = []
        try:
            staged_rows = list(db.execute(
                "SELECT * FROM cas_manifest WHERE status='staged' ORDER BY rowid"))
            for row in staged_rows:
                src = db.execute(
                    'SELECT hash,raw FROM source_file WHERE id=?',
                    (row['source_id'],)).fetchone()
                data = bytes(src['raw'])
                if not data and row['byte_length']:
                    raise RecoveryError(
                        f'staged_manifest_without_recoverable_bytes:{row["manifest_id"]}')
                manifest, blobs = _chunk_blobs(data, row['representation'])
                expected_id = _sha256(
                    f'{row["source_id"]}|{row["representation"]}|{src["hash"]}|'
                    f'{_canonical(manifest)}'.encode())
                if expected_id != row['manifest_id']:
                    db.execute(
                        'UPDATE cas_manifest SET status=?, aborted_at=? WHERE manifest_id=?',
                        ('aborted', now, row['manifest_id']))
                    db.commit()
                    continue
                for digest, span in blobs:
                    if not store.exists(digest):
                        store.put(span)
                if _sha256(reassemble(manifest, store.get)) != src['hash']:
                    raise RecoveryError(f'reassembly_hash_mismatch:{row["manifest_id"]}')
                gen = _publish(db, row['manifest_id'], now)
                resumed.append({'manifest_id': row['manifest_id'], 'generation': gen})

            reclaimed = []
            pointers = list(db.execute(
                'SELECT source_id FROM cas_pointer WHERE blob_reclaimed=0'))
            for pointer in pointers:
                if _reclaim_blob(db, store, pointer['source_id'], now):
                    reclaimed.append(pointer['source_id'])

            verification = verify_archive(db_path, now=now)
            if not verification['ok']:
                raise RecoveryError(json.dumps(verification, ensure_ascii=False))
            return {
                'recovered_at': now,
                'temp_files_swept': swept_tmp,
                'staged_resumed': resumed,
                'blobs_reclaimed': reclaimed,
                'verification': verification,
            }
        finally:
            db.close()


# --------------------------------------------------------------------------- #
# Verification and storage accounting
# --------------------------------------------------------------------------- #
def verify_archive(db_path, *, now: float = None) -> dict:
    store = ContentStore.for_db(db_path)
    db = connect(db_path)
    try:
        sources = []
        ok = True
        for src in db.execute('SELECT * FROM source_file ORDER BY id'):
            entry = {'source_id': src['id'], 'name': src['name'],
                     'source_hash': src['hash'], 'byte_length': len(src['raw']),
                     'archived': False, 'verified': False}
            pointer = db.execute(
                'SELECT * FROM cas_pointer WHERE source_id=?',
                (src['id'],)).fetchone()
            if pointer is not None:
                entry['archived'] = True
                entry['blob_reclaimed'] = bool(pointer['blob_reclaimed'])
                row = db.execute(
                    'SELECT * FROM cas_manifest WHERE manifest_id=?',
                    (pointer['manifest_id'],)).fetchone()
                try:
                    manifest = json.loads(row['manifest_json'])
                    missing = [h for h in manifest_chunk_hashes(manifest)
                               if not store.exists(h)]
                    if missing:
                        raise ArchiveError(f'chunks_missing:{len(missing)}')
                    rebuilt = reassemble(manifest, store.get)
                    entry['verified'] = _sha256(rebuilt) == src['hash']
                    if entry['verified'] and src['raw'] != b'':
                        # Old BLOB still present during coexistence: prove the
                        # new copy is byte-identical before anyone reclaims it.
                        entry['raw_matches_archive'] = rebuilt == bytes(src['raw'])
                except ArchiveError as exc:
                    entry['error'] = str(exc)
            else:
                entry['verified'] = _sha256(bytes(src['raw'])) == src['hash']
            ok = ok and entry['verified']
            sources.append(entry)
        return {'ok': ok, 'sources': sources}
    finally:
        db.close()


def storage_accounting(db_path) -> dict:
    """Honest physical ledger: unique on-disk chunks vs logical references."""
    store = ContentStore.for_db(db_path)
    db = connect(db_path)
    try:
        physical = store.physical_accounting()
        published = list(db.execute(
            "SELECT * FROM cas_manifest WHERE status='published'"))
        staged = list(db.execute(
            "SELECT * FROM cas_manifest WHERE status='staged'"))
        logical_refs = 0
        referenced = set()
        per_source = []
        for row in published:
            manifest = json.loads(row['manifest_json'])
            hashes = manifest_chunk_hashes(manifest)
            logical_refs += len(hashes)
            referenced.update(hashes)
            per_source.append({
                'source_id': row['source_id'],
                'representation': row['representation'],
                'generation': row['source_gen'],
                'byte_length': row['byte_length'],
                'chunk_refs': len(hashes),
                'manifest_bytes': len(row['manifest_json'].encode('utf-8')),
            })
        raw_row = db.execute(
            'SELECT COALESCE(SUM(length(raw)),0) AS raw_bytes,'
            'SUM(CASE WHEN length(raw)=0 THEN 1 ELSE 0 END) AS empty_blobs,'
            'COUNT(*) AS n FROM source_file').fetchone()
        reclaimed_row = db.execute(
            'SELECT COUNT(*) AS n FROM cas_pointer WHERE blob_reclaimed=1'
        ).fetchone()
        db_file = Path(db_path)
        return {
            'representations_published': sorted(
                {e['representation'] for e in per_source}),
            'sources_archived': len({e['source_id'] for e in per_source}),
            'staged_manifests': len(staged),
            'logical_chunk_refs': logical_refs,
            'unique_referenced_chunks': len(referenced),
            'shared_refs_saved': logical_refs - len(referenced),
            'manifest_bytes': sum(e['manifest_bytes'] for e in per_source),
            'raw_blob_bytes_remaining': raw_row['raw_bytes'],
            'sources_total': raw_row['n'],
            'blobs_reclaimed': reclaimed_row['n'],
            'db_file_bytes': db_file.stat().st_size if db_file.exists() else 0,
            'per_source': per_source,
            **physical,
        }
    finally:
        db.close()


# --------------------------------------------------------------------------- #
# Safe garbage collection
# --------------------------------------------------------------------------- #
def run_gc(db_path, *, grace_seconds: float = 60, now: float = None,
           vacuum: bool = False) -> dict:
    """Remove only chunks no published/visible manifest or live pin references.

    The grace period is an additional floor on age, never a substitute for the
    active-reference check: anything reachable from a manifest an unexpired pin
    can see is protected regardless of age.
    """
    now = time.time() if now is None else now
    store = ContentStore.for_db(db_path)
    # Exclusive lock: no migration is injecting chunks while we prune.
    with gc_lock(db_path):
        db = connect(db_path)
        detail = {}
        try:
            # 1. Sweep stale injection temp files and expired reader pins.
            temp_swept = 0
            if store.root.is_dir():
                for tmp in list(store.iter_temp_files()):
                    if now - tmp.stat().st_mtime >= grace_seconds:
                        tmp.unlink()
                        temp_swept += 1
            expired_pins = db.execute(
                'DELETE FROM cas_pin WHERE expires_at<=?', (now,)).rowcount
            db.commit()

            active_pins = [r['generation'] for r in db.execute(
                'SELECT generation FROM cas_pin WHERE expires_at>?', (now,))]
            min_pin_gen = min(active_pins) if active_pins else None

            published = list(db.execute(
                "SELECT * FROM cas_manifest WHERE status='published'"))
            current_pointer_ids = {r['manifest_id'] for r in db.execute(
                'SELECT manifest_id FROM cas_pointer')}

            # Decide which manifest rows survive this GC. A row is retained when
            # it is the current pointer, an active pin can still read it, or it
            # has not outlived the grace window. Everything else is pruned first;
            # chunk protection is then computed only from the surviving rows so
            # no dangling reference can ever remain.
            retained_manifest_ids = set()
            pruned_manifests = 0
            for row in published:
                is_current = row['manifest_id'] in current_pointer_ids
                visible_to_pin = min_pin_gen is not None \
                    and row['source_gen'] <= min_pin_gen
                old_enough = row['published_at'] is not None \
                    and now - row['published_at'] >= grace_seconds
                if is_current or visible_to_pin or not old_enough:
                    retained_manifest_ids.add(row['manifest_id'])
                else:
                    db.execute('DELETE FROM cas_manifest WHERE manifest_id=?',
                               (row['manifest_id'],))
                    pruned_manifests += 1

            # Staged attempts inside the grace window may still resume; aged ones
            # are aborted and their chunks become unreferenced.
            for row in db.execute("SELECT * FROM cas_manifest WHERE status='staged'"):
                if now - row['created_at'] >= grace_seconds:
                    db.execute(
                        'UPDATE cas_manifest SET status=?, aborted_at=? WHERE manifest_id=?',
                        ('aborted', now, row['manifest_id']))
            db.commit()

            protected_chunks = set()
            retained_rows = list(db.execute(
                "SELECT * FROM cas_manifest WHERE status='published'"))
            for row in retained_rows:
                if row['manifest_id'] in retained_manifest_ids:
                    protected_chunks.update(
                        manifest_chunk_hashes(json.loads(row['manifest_json'])))
            for row in db.execute("SELECT * FROM cas_manifest WHERE status='staged'"):
                protected_chunks.update(
                    manifest_chunk_hashes(json.loads(row['manifest_json'])))

            # Delete unreachable physical chunks. Manifest-level grace plus the
            # live-pin/current-pointer reference check above are the safety
            # mechanism; object mtimes follow the wall clock and must not add a
            # second, untestable age floor on top of them.
            removed_chunks = 0
            freed_bytes = 0
            if store.root.is_dir():
                for obj in list(store.iter_objects()):
                    digest = obj.parent.name + obj.name
                    if digest in protected_chunks:
                        continue
                    freed_bytes += obj.stat().st_size
                    if store.remove(digest):
                        removed_chunks += 1

            # Reclaim any BLOB whose switched manifest now verifies.
            reclaimed = []
            for pointer in db.execute(
                    'SELECT source_id FROM cas_pointer WHERE blob_reclaimed=0'):
                if _reclaim_blob(db, store, pointer['source_id'], now):
                    reclaimed.append(pointer['source_id'])

            if vacuum:
                db.execute('PRAGMA wal_checkpoint(TRUNCATE)')
                db.commit()
                db.execute('PRAGMA incremental_vacuum')

            detail = {
                'active_pins': len(active_pins),
                'expired_pins_swept': expired_pins,
                'protected_chunks': len(protected_chunks),
                'temp_files_swept': temp_swept,
                'freed_chunk_bytes': freed_bytes,
            }
            with db:
                db.execute(
                    'INSERT INTO cas_gc_log(ran_at,removed_chunks,'
                    'removed_manifests,reclaimed_blobs,detail) VALUES(?,?,?,?,?)',
                    (now, removed_chunks, pruned_manifests, len(reclaimed),
                     json.dumps(detail, ensure_ascii=False)))
            return {
                'ran_at': now,
                'grace_seconds': grace_seconds,
                'removed_chunks': removed_chunks,
                'removed_manifests': pruned_manifests,
                'reclaimed_blobs': reclaimed,
                **detail,
            }
        finally:
            db.close()


# --------------------------------------------------------------------------- #
# Frozen audit case (original entry point, now archive-aware)
# --------------------------------------------------------------------------- #
def register(db_path, contract_path):
    raw = Path(contract_path).read_bytes()
    contract = json.loads(raw)
    store = ContentStore.for_db(db_path)
    db = connect(db_path)
    db.executescript('''CREATE TABLE IF NOT EXISTS archive_case(
      id TEXT PRIMARY KEY, contract_sha256 TEXT NOT NULL,
      contract_json TEXT NOT NULL, source_digest TEXT NOT NULL
    );''')
    rows = [dict(r) for r in db.execute(
        'SELECT id,hash FROM source_file ORDER BY id')]
    if len(rows) < 2:
        raise ValueError('needs_multiple_source_files')
    snapshot = []
    for r in rows:
        # Works before migration (raw BLOB) and after (manifest reassembly).
        source_bytes = _read_source_bytes(db, store, r['id'])
        snapshot.append({'id': r['id'], 'hash': r['hash'],
                         'bytes': len(source_bytes),
                         'raw_sha256': _sha256(source_bytes)})
    digest = hashlib.sha256(
        json.dumps(snapshot, sort_keys=True).encode()).hexdigest()
    with db:
        db.execute('INSERT INTO archive_case VALUES (?,?,?,?)',
                   (contract['case_id'], hashlib.sha256(raw).hexdigest(),
                    raw.decode(), digest))
    db.close()
    return contract['case_id']
