import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'api.dart';
import 'errors.dart';
import 'io.dart';

typedef EntryOpener = ChunkSink? Function(PzEntry entry);
typedef EntryCloser = void Function(PzEntry entry);

Future<void> pzYield() => Future<void>.delayed(Duration.zero);

abstract class ReaderBase implements ArchiveReader {
  ReaderBase(this.path);

  final String path;

  void decodeEntry(PzEntry entry, ChunkSink sink, CancelToken? cancel);

  void decodeMany(
    List<PzEntry> wanted,
    EntryOpener open,
    EntryCloser close,
    CancelToken? cancel,
  ) {
    for (final PzEntry e in wanted) {
      if (cancel != null && cancel.isCancelled) throw const PzCancelled();
      final ChunkSink? s = open(e);
      if (s == null) continue;
      decodeEntry(e, s, cancel);
      close(e);
    }
  }

  @override
  Stream<List<int>> openRead(PzEntry entry) {
    final StreamController<List<int>> c = StreamController<List<int>>();
    Future<void>(() {
      try {
        decodeEntry(entry, (Uint8List b, int s, int e) {
          if (c.isClosed) throw const PzCancelled();
          c.add(Uint8List.fromList(Uint8List.sublistView(b, s, e)));
        }, null);
      } on PzCancelled {
      } catch (e, st) {
        if (!c.isClosed) c.addError(e, st);
      }
      if (!c.isClosed) c.close();
    });
    return c.stream;
  }

  @override
  Future<void> extractTo(
    PzEntry entry,
    void Function(Uint8List chunk) sink, {
    CancelToken? cancel,
  }) async {
    decodeMany(
      <PzEntry>[entry],
      (PzEntry e) => (Uint8List b, int s, int en) => sink(Uint8List.sublistView(b, s, en)),
      (PzEntry e) {},
      cancel,
    );
  }

  @override
  Future<Uint8List> readBytes(PzEntry entry, {int maxBytes = 16 * 1024 * 1024}) async {
    if (entry.size > maxBytes) {
      throw PzException('The entry is bigger than $maxBytes bytes.');
    }
    final ByteBuilder out = ByteBuilder(entry.size > 0 ? entry.size : 16);
    decodeMany(
      <PzEntry>[entry],
      (PzEntry e) => (Uint8List b, int s, int en) {
            if (out.length + (en - s) > maxBytes) {
              throw PzException('The entry is bigger than $maxBytes bytes.');
            }
            out.addBytes(b, s, en);
          },
      (PzEntry e) {},
      null,
    );
    return out.toBytes();
  }

  @override
  Future<void> extractEntry(
    PzEntry entry,
    String destPath, {
    void Function(int bytes)? onProgress,
    CancelToken? cancel,
  }) async {
    final _FileOut? out = _FileOut.create(destPath, entry, onProgress);
    if (out == null) return;
    try {
      decodeMany(<PzEntry>[entry], (PzEntry e) => out.sink, (PzEntry e) {}, cancel);
      out.finish(true);
    } catch (_) {
      out.finish(false);
      rethrow;
    }
  }

  @override
  Future<List<String>> extractAll(
    String destDir, {
    bool Function(PzEntry entry)? filter,
    void Function(PzEntry entry)? onFile,
    void Function(int bytes)? onProgress,
    CancelToken? cancel,
  }) async {
    final List<String> skipped = <String>[];
    final List<PzEntry> wanted = <PzEntry>[];
    final List<PzEntry> links = <PzEntry>[];
    final Map<PzEntry, String> dest = Map<PzEntry, String>.identity();
    Directory(destDir).createSync(recursive: true);
    for (final PzEntry e in entries) {
      if (filter != null && !filter(e)) continue;
      final String? rel = safeRelative(e.path);
      if (rel == null) {
        skipped.add(e.path);
        continue;
      }
      final String target = '$destDir/$rel';
      dest[e] = target;
      if (e.isDir) {
        Directory(target).createSync(recursive: true);
      } else if (e.linkTarget != null) {
        links.add(e);
      } else {
        wanted.add(e);
      }
    }
    _FileOut? current;
    try {
      decodeMany(
        wanted,
        (PzEntry e) {
          onFile?.call(e);
          final _FileOut? o = _FileOut.create(dest[e]!, e, onProgress);
          current = o;
          return o?.sink;
        },
        (PzEntry e) {
          current?.finish(true);
          current = null;
        },
        cancel,
      );
    } catch (_) {
      current?.finish(false);
      rethrow;
    }
    for (final PzEntry e in links) {
      try {
        final String t = dest[e]!;
        final Directory parent = File(t).parent;
        if (!parent.existsSync()) parent.createSync(recursive: true);
        final Link l = Link(t);
        if (l.existsSync() || File(t).existsSync()) {
          if (l.existsSync()) l.deleteSync();
        }
        l.createSync(e.linkTarget!);
      } catch (_) {
      }
    }
    await pzYield();
    return skipped;
  }
}

String? safeRelative(String name) {
  var n = name.replaceAll('\\', '/');
  while (n.startsWith('/')) {
    n = n.substring(1);
  }
  if (n.isEmpty) return null;
  final List<String> parts = n.split('/');
  final List<String> keep = <String>[];
  for (final String p in parts) {
    if (p.isEmpty || p == '.') continue;
    if (p == '..') return null;
    if (p.contains('\u0000')) return null;
    keep.add(p);
  }
  if (keep.isEmpty) return null;
  if (keep.first.length == 2 && keep.first.endsWith(':')) return null;
  return keep.join('/');
}

class _FileOut {
  _FileOut._(this._path, this._raf, this._entry, this._progress);

  final String _path;
  final RandomAccessFile _raf;
  final PzEntry _entry;
  final void Function(int)? _progress;
  bool _done = false;

  static _FileOut? create(String path, PzEntry e, void Function(int)? progress) {
    final File f = File(path);
    final Directory parent = f.parent;
    if (!parent.existsSync()) parent.createSync(recursive: true);
    if (e.linkTarget != null || e.isDir) {
      if (e.isDir) Directory(path).createSync(recursive: true);
      return null;
    }
    final RandomAccessFile raf = f.openSync(mode: FileMode.write);
    return _FileOut._(path, raf, e, progress);
  }

  void sink(Uint8List b, int s, int e) {
    _raf.writeFromSync(b, s, e);
    _progress?.call(e - s);
  }

  void finish(bool ok) {
    if (_done) return;
    _done = true;
    try {
      _raf.closeSync();
    } catch (_) {}
    if (!ok) {
      try {
        File(_path).deleteSync();
      } catch (_) {}
      return;
    }
    final DateTime? m = _entry.modified;
    if (m != null) {
      try {
        File(_path).setLastModifiedSync(m);
      } catch (_) {}
    }
    final int? mode = _entry.mode;
    if (mode != null && PzHooks.chmod != null) {
      try {
        PzHooks.chmod!(_path, mode & 0xFFF);
      } catch (_) {}
    }
  }
}
