import 'dart:io';
import 'dart:typed_data';

import 'api.dart';
import 'errors.dart';
import 'gzip.dart';
import 'io.dart';
import 'sevenz_reader.dart';
import 'single_reader.dart';
import 'tar.dart';
import 'xz.dart';
import 'zip_reader.dart';

bool _isTarBlock(Uint8List b) {
  if (b.length < 512) return false;
  if (b[257] == 0x75 && b[258] == 0x73 && b[259] == 0x74 && b[260] == 0x61 && b[261] == 0x72) {
    return true;
  }
  var sum = 0;
  var allZero = true;
  for (var i = 0; i < 512; i++) {
    if (b[i] != 0) allZero = false;
    sum += (i >= 148 && i < 156) ? 0x20 : b[i];
  }
  if (allZero) return false;
  var stored = 0;
  var i = 148;
  while (i < 156 && b[i] == 0x20) {
    i++;
  }
  while (i < 156 && b[i] >= 0x30 && b[i] <= 0x37) {
    stored = (stored << 3) | (b[i] - 0x30);
    i++;
  }
  return stored == sum && sum > 0 && b[0] != 0;
}

Uint8List? _firstBlock(String path, bool xz) {
  RandomAccessFile? raf;
  try {
    raf = File(path).openSync();
    final int len = raf.lengthSync();
    final ByteBuilder got = ByteBuilder(512);
    void sink(Uint8List b, int s, int e) {
      final int need = 512 - got.length;
      got.addBytes(b, s, (e - s) > need ? s + need : e);
      if (got.length >= 512) throw const PzStop();
    }

    try {
      if (xz) {
        xzDecode(FileInput(raf, 0, len), sink);
      } else {
        gzDecode(raf, len, sink);
      }
    } on PzStop {
    }
    return got.length >= 512 ? got.toBytes() : null;
  } catch (_) {
    return null;
  } finally {
    raf?.closeSync();
  }
}

Future<ArchiveFormat?> detectArchiveFormat(String path) async {
  final File f = File(path);
  if (!f.existsSync()) return null;
  final RandomAccessFile raf = f.openSync();
  Uint8List head;
  try {
    head = Uint8List(512);
    final int n = raf.readIntoSync(head, 0, 512);
    if (n < 512) head = Uint8List.sublistView(head, 0, n);
  } finally {
    raf.closeSync();
  }
  final String lower = path.toLowerCase();
  if (head.length >= 4 && head[0] == 0x50 && head[1] == 0x4B && (head[2] == 3 || head[2] == 5)) {
    return ArchiveFormat.zip;
  }
  if (head.length >= 6 &&
      head[0] == 0x37 &&
      head[1] == 0x7A &&
      head[2] == 0xBC &&
      head[3] == 0xAF &&
      head[4] == 0x27 &&
      head[5] == 0x1C) {
    return ArchiveFormat.sevenZip;
  }
  if (head.length >= 2 && head[0] == 0x1F && head[1] == 0x8B) {
    if (lower.endsWith('.tar.gz') || lower.endsWith('.tgz')) return ArchiveFormat.tarGz;
    final Uint8List? blk = _firstBlock(path, false);
    return (blk != null && _isTarBlock(blk)) ? ArchiveFormat.tarGz : ArchiveFormat.gzip;
  }
  if (head.length >= 6 &&
      head[0] == 0xFD &&
      head[1] == 0x37 &&
      head[2] == 0x7A &&
      head[3] == 0x58 &&
      head[4] == 0x5A &&
      head[5] == 0x00) {
    if (lower.endsWith('.tar.xz') || lower.endsWith('.txz')) return ArchiveFormat.tarXz;
    final Uint8List? blk = _firstBlock(path, true);
    return (blk != null && _isTarBlock(blk)) ? ArchiveFormat.tarXz : ArchiveFormat.xz;
  }
  if (_isTarBlock(head)) return ArchiveFormat.tar;
  return null;
}

Future<ArchiveReader> openArchive(String path, String? password, CancelToken? cancel) async {
  final File f = File(path);
  if (!f.existsSync()) throw PzException('File not found: $path');
  final ArchiveFormat? fmt = await detectArchiveFormat(path);
  if (fmt == null) {
    final RandomAccessFile raf = f.openSync();
    try {
      final Uint8List h = Uint8List(8);
      raf.readIntoSync(h, 0, 8);
      if (h[0] == 0x52 && h[1] == 0x61 && h[2] == 0x72 && h[3] == 0x21) {
        throw const PzUnsupported('RAR archives are not supported.');
      }
      if (h[0] == 0x42 && h[1] == 0x5A && h[2] == 0x68) {
        throw const PzUnsupported('bzip2 files are not supported.');
      }
    } finally {
      raf.closeSync();
    }
    throw const PzUnsupported('This is not a supported archive.');
  }
  switch (fmt) {
    case ArchiveFormat.zip:
      return ZipReader.open(path, password);
    case ArchiveFormat.sevenZip:
      return SevenZReader.open(path, password);
    case ArchiveFormat.tar:
    case ArchiveFormat.tarGz:
    case ArchiveFormat.tarXz:
      return TarReader.open(path, fmt);
    case ArchiveFormat.gzip:
    case ArchiveFormat.xz:
      return SingleFileReader.open(path, fmt);
  }
}
