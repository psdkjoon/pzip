import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'api.dart';
import 'errors.dart';
import 'reader_base.dart' show pzYield;

class EntryMeta {
  const EntryMeta({
    required this.path,
    this.isDir = false,
    this.linkTarget,
    this.size = 0,
    this.modified,
    this.mode,
  });

  final String path;
  final bool isDir;
  final String? linkTarget;

  final int size;
  final DateTime? modified;

  final int? mode;

  bool get isLink => linkTarget != null;
}

typedef PutChunk = void Function(Uint8List buf, int start, int end);

String cleanArchivePath(String p) {
  var n = p.replaceAll('\\', '/');
  while (n.startsWith('/')) {
    n = n.substring(1);
  }
  while (n.endsWith('/')) {
    n = n.substring(0, n.length - 1);
  }
  final List<String> parts = n.split('/').where((String s) => s.isNotEmpty && s != '.').toList();
  if (parts.isEmpty || parts.contains('..')) {
    throw PzException('Bad name in archive: $p');
  }
  return parts.join('/');
}

abstract class WriterBase implements ArchiveWriter {
  WriterBase(this.outPath, this.options, this.onProgress, this.cancel);

  final String outPath;
  final WriteOptions options;
  final void Function(int bytes)? onProgress;
  final CancelToken? cancel;
  bool _finished = false;
  int _sinceYield = 0;

  void addEntry(EntryMeta meta, void Function(PutChunk put)? produce);

  void finishFormat();

  void closeRaw();

  void checkCancel() {
    if (cancel != null && cancel!.isCancelled) throw const PzCancelled();
  }

  @override
  Future<void> addFile(String diskPath, String archivePath) async {
    checkCancel();
    final String name = cleanArchivePath(archivePath);
    final FileStat st = FileStat.statSync(diskPath);
    if (st.type == FileSystemEntityType.notFound) {
      throw PzException('File not found: $diskPath');
    }
    if (st.type == FileSystemEntityType.directory) {
      await addDirectory(name, modified: st.modified, mode: options.keepPermissions ? st.mode & 0xFFF : null);
      return;
    }
    final int? mode = options.keepPermissions ? st.mode & 0xFFF : null;
    final EntryMeta meta = EntryMeta(path: name, size: st.size, modified: st.modified, mode: mode);
    addEntry(meta, (PutChunk put) {
      final RandomAccessFile f = File(diskPath).openSync();
      try {
        final Uint8List buf = Uint8List(262144);
        while (true) {
          checkCancel();
          final int n = f.readIntoSync(buf, 0, buf.length);
          if (n <= 0) break;
          put(buf, 0, n);
          onProgress?.call(n);
          _sinceYield += n;
        }
      } finally {
        f.closeSync();
      }
    });
    if (_sinceYield >= 4 * 1024 * 1024) {
      _sinceYield = 0;
      await pzYield();
    }
  }

  @override
  Future<void> addDirectory(String archivePath, {DateTime? modified, int? mode}) async {
    checkCancel();
    addEntry(
      EntryMeta(path: cleanArchivePath(archivePath), isDir: true, modified: modified, mode: mode),
      null,
    );
  }

  @override
  Future<void> addBytes(String archivePath, Uint8List bytes, {DateTime? modified}) async {
    checkCancel();
    addEntry(
      EntryMeta(
        path: cleanArchivePath(archivePath),
        size: bytes.length,
        modified: modified ?? DateTime.now(),
        mode: 0x1A4,
      ),
      (PutChunk put) {
        if (bytes.isNotEmpty) put(bytes, 0, bytes.length);
        onProgress?.call(bytes.length);
      },
    );
  }

  @override
  Future<void> addSymlink(String archivePath, String target) async {
    checkCancel();
    final Uint8List t = Uint8List.fromList(utf8.encode(target));
    addEntry(
      EntryMeta(
        path: cleanArchivePath(archivePath),
        linkTarget: target,
        size: t.length,
        modified: DateTime.now(),
        mode: 0x1FF,
      ),
      (PutChunk put) {
        if (t.isNotEmpty) put(t, 0, t.length);
      },
    );
  }

  @override
  Future<void> close() async {
    if (_finished) return;
    _finished = true;
    try {
      finishFormat();
    } catch (_) {
      closeRaw();
      try {
        File(outPath).deleteSync();
      } catch (_) {}
      rethrow;
    }
  }

  @override
  Future<void> abort() async {
    if (_finished) {
      return;
    }
    _finished = true;
    try {
      closeRaw();
    } catch (_) {}
    try {
      File(outPath).deleteSync();
    } catch (_) {}
  }
}
