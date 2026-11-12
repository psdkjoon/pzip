import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'deflate.dart';
import 'errors.dart';
import 'hash.dart';
import 'io.dart';

class GzInfo {
  GzInfo(this.name, this.mtime, this.dataStart);

  final String? name;

  final DateTime? mtime;

  final int dataStart;
}

GzInfo readGzHeader(RandomAccessFile raf, int fileLen) {
  if (fileLen < 18) throw const PzCorrupt('This is not a gzip file.');
  final FileInput input = FileInput(raf, 0, fileLen);
  if (input.readByte() != 0x1F || input.readByte() != 0x8B) {
    throw const PzCorrupt('This is not a gzip file.');
  }
  if (input.readByte() != 8) throw const PzUnsupported('Unknown gzip method.');
  final int flg = input.readByte();
  final int mt = input.readU32le();
  input.readByte();
  input.readByte();
  if ((flg & 4) != 0) {
    final int n = input.readU16le();
    input.skip(n);
  }
  String? name;
  if ((flg & 8) != 0) {
    final List<int> bytes = <int>[];
    while (true) {
      final int c = input.readByte();
      if (c == 0) break;
      bytes.add(c);
      if (bytes.length > 4096) throw const PzCorrupt('Bad gzip header.');
    }
    name = utf8.decode(bytes, allowMalformed: true);
  }
  if ((flg & 16) != 0) {
    while (input.readByte() != 0) {}
  }
  if ((flg & 2) != 0) input.skip(2);
  return GzInfo(
    name,
    mt == 0 ? null : DateTime.fromMillisecondsSinceEpoch(mt * 1000),
    input.position,
  );
}

int readGzSize(RandomAccessFile raf, int fileLen) {
  raf.setPositionSync(fileLen - 4);
  final Uint8List b = Uint8List(4);
  raf.readIntoSync(b, 0, 4);
  return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
}

int gzDecode(RandomAccessFile raf, int fileLen, ChunkSink sink, {CancelToken? cancel}) {
  final GzInfo info = readGzHeader(raf, fileLen);
  final int end = fileLen - 8;
  if (info.dataStart > end) throw const PzCorrupt('The file ends too early.');
  raf.setPositionSync(end);
  final Uint8List f = Uint8List(8);
  raf.readIntoSync(f, 0, 8);
  final int crcStored = f[0] | (f[1] << 8) | (f[2] << 16) | (f[3] << 24);
  final int sizeStored = f[4] | (f[5] << 8) | (f[6] << 16) | (f[7] << 24);
  final Crc32 crc = Crc32();
  var produced = 0;
  inflateRaw(FileInput(raf, info.dataStart, end), end - info.dataStart,
      (Uint8List b, int s, int e) {
    crc.add(Uint8List.sublistView(b, s, e));
    produced += e - s;
    sink(b, s, e);
  }, cancel: cancel);
  if (crc.value != crcStored || (produced & 0xFFFFFFFF) != sizeStored) {
    throw const PzCorrupt('The gzip data is damaged (bad checksum).');
  }
  return produced;
}

class GzSink extends DataSink {
  GzSink(this._out, int level) {
    _out.add(<int>[0x1F, 0x8B, 8, 0, 0, 0, 0, 0, 0, 3]);
    _deflater = RawDeflater(level, (Uint8List o) => _out.add(o, 0, o.length));
  }

  final BufferedOut _out;
  late final RawDeflater _deflater;
  final Crc32 _crc = Crc32();
  int _size = 0;

  @override
  void add(Uint8List buf, int start, int end) {
    _crc.add(Uint8List.sublistView(buf, start, end));
    _size += end - start;
    _deflater.add(buf, start, end);
  }

  @override
  void close() {
    _deflater.close();
    final ByteBuilder t = ByteBuilder(8);
    t.addU32le(_crc.value);
    t.addU32le(_size & 0xFFFFFFFF);
    _out.add(t.view());
    _out.close();
  }

  @override
  void closeRaw() {
    try {
      _out.close();
    } catch (_) {}
  }
}
