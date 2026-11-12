import 'dart:io';
import 'dart:typed_data';

import 'api.dart';
import 'errors.dart';
import 'gzip.dart';
import 'io.dart';
import 'reader_base.dart';
import 'xz.dart';

class SingleFileReader extends ReaderBase {
  SingleFileReader._(super.path, this._format, this._raf, this._len, this._entry);

  final ArchiveFormat _format;
  final RandomAccessFile _raf;
  final int _len;
  final PzEntry _entry;

  static SingleFileReader open(String path, ArchiveFormat format) {
    final RandomAccessFile raf = File(path).openSync();
    try {
      final int len = raf.lengthSync();
      final String base = path.split('/').last;
      String name;
      int size;
      DateTime? mtime;
      if (format == ArchiveFormat.gzip) {
        final GzInfo info = readGzHeader(raf, len);
        size = readGzSize(raf, len);
        mtime = info.mtime;
        name = (info.name != null && info.name!.isNotEmpty)
            ? info.name!.split('/').last
            : _strip(base, '.gz');
      } else {
        raf.setPositionSync(0);
        final Uint8List m = Uint8List(6);
        if (raf.readIntoSync(m, 0, 6) < 6 || m[0] != 0xFD || m[1] != 0x37 || m[2] != 0x7A) {
          throw const PzCorrupt('This is not an xz file.');
        }
        size = xzUncompressedSize(raf, len);
        name = _strip(base, '.xz');
      }
      final PzEntry e = PzEntry(
        path: name,
        isDir: false,
        size: size < 0 ? 0 : size,
        packedSize: len,
        modified: mtime ?? File(path).lastModifiedSync(),
      );
      return SingleFileReader._(path, format, raf, len, e);
    } catch (_) {
      raf.closeSync();
      rethrow;
    }
  }

  static String _strip(String base, String ext) {
    if (base.toLowerCase().endsWith(ext) && base.length > ext.length) {
      return base.substring(0, base.length - ext.length);
    }
    return '$base.out';
  }

  @override
  ArchiveFormat get format => _format;

  @override
  List<PzEntry> get entries => <PzEntry>[_entry];

  @override
  bool get hasEncryptedEntries => false;

  @override
  bool get isSolid => false;

  @override
  Future<void> close() async {
    try {
      _raf.closeSync();
    } catch (_) {}
  }

  @override
  void decodeEntry(PzEntry entry, ChunkSink sink, CancelToken? cancel) {
    if (_format == ArchiveFormat.gzip) {
      gzDecode(_raf, _len, sink, cancel: cancel);
    } else {
      xzDecode(FileInput(_raf, 0, _len), sink, cancel: cancel);
    }
  }
}
