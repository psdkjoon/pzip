import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'aes.dart';
import 'api.dart';
import 'deflate.dart';
import 'errors.dart';
import 'hash.dart';
import 'io.dart';
import 'writer_base.dart';

class ZipWriter extends WriterBase {
  ZipWriter._(
    super.outPath,
    super.options,
    super.onProgress,
    super.cancel,
    this._out,
  );

  final BufferedOut _out;
  final ByteBuilder _cd = ByteBuilder(4096);
  int _count = 0;

  static ZipWriter create(
    String outPath,
    WriteOptions options,
    void Function(int)? onProgress,
    CancelToken? cancel,
  ) {
    final RandomAccessFile f = File(outPath).openSync(mode: FileMode.write);
    return ZipWriter._(outPath, options, onProgress, cancel, BufferedOut(f));
  }

  static int _dosTime(DateTime d) => (d.hour << 11) | (d.minute << 5) | (d.second ~/ 2);

  static int _dosDate(DateTime d) {
    if (d.year < 1980) return (1 << 5) | 1;
    final int y = d.year > 2107 ? 127 : d.year - 1980;
    return (y << 9) | (d.month << 5) | d.day;
  }

  @override
  void addEntry(EntryMeta m, void Function(PutChunk put)? produce) {
    checkCancel();
    final bool isDir = m.isDir;
    final Uint8List nameBytes = Uint8List.fromList(utf8.encode(isDir ? '${m.path}/' : m.path));
    final DateTime mod = m.modified ?? DateTime.now();
    final int unixTime = mod.millisecondsSinceEpoch ~/ 1000;
    final bool aes = options.password != null && !isDir && !m.isLink && m.size > 0;
    final int level = options.level;
    final int actualMethod = (isDir || m.isLink || m.size == 0 || level <= 0) ? 0 : 8;
    final bool zip64 = m.size >= 0xFFFFFFFF;
    final int mode = m.mode ?? (isDir ? 0x1ED : 0x1A4);
    final int typeBits = isDir ? 0x4000 : (m.isLink ? 0xA000 : 0x8000);
    final int extAttr = (((typeBits | mode) & 0xFFFF) << 16) | (isDir ? 0x10 : 0);
    final int flags = 0x800 | (aes ? 1 : 0);
    final int method = aes ? 99 : actualMethod;
    final int needed = aes ? 51 : (zip64 ? 45 : (actualMethod == 8 ? 20 : (isDir ? 20 : 10)));

    final ByteBuilder ex = ByteBuilder(64);
    int zip64Pos = -1;
    if (zip64) {
      ex.addU16le(0x0001);
      ex.addU16le(16);
      zip64Pos = ex.length;
      ex.addU64le(0);
      ex.addU64le(0);
    }
    ex.addU16le(0x5455);
    ex.addU16le(5);
    ex.addByte(1);
    ex.addU32le(unixTime);
    if (aes) {
      ex.addU16le(0x9901);
      ex.addU16le(7);
      ex.addU16le(2);
      ex.addByte(0x41);
      ex.addByte(0x45);
      ex.addByte(3);
      ex.addU16le(actualMethod);
    }
    final Uint8List extra = ex.toBytes();

    final int headerPos = _out.position;
    final ByteBuilder h = ByteBuilder(64 + nameBytes.length + extra.length);
    h.addU32le(0x04034b50);
    h.addU16le(needed);
    h.addU16le(flags);
    h.addU16le(method);
    h.addU16le(_dosTime(mod));
    h.addU16le(_dosDate(mod));
    h.addU32le(0);
    h.addU32le(zip64 ? 0xFFFFFFFF : 0);
    h.addU32le(zip64 ? 0xFFFFFFFF : 0);
    h.addU16le(nameBytes.length);
    h.addU16le(extra.length);
    h.addBytes(nameBytes);
    h.addBytes(extra);
    _out.add(h.view());

    var csize = 0;
    var usize = 0;
    final Crc32 crc = Crc32();

    if (produce != null) {
      HmacHasher? mac;
      AesCtr? ctr;
      void emitPacked(Uint8List b, int s, int e) {
        if (ctr != null) {
          final Uint8List enc = ctr.process(Uint8List.sublistView(b, s, e));
          mac!.add(enc);
          _out.add(enc);
        } else {
          _out.add(b, s, e);
        }
        csize += e - s;
      }

      if (aes) {
        final Uint8List salt = randomBytes(16);
        final Uint8List dk = pbkdf2HmacSha1(
          Uint8List.fromList(utf8.encode(options.password!)),
          salt,
          1000,
          66,
        );
        final Uint8List counter = Uint8List(16)..[0] = 1;
        ctr = AesCtr(Uint8List.sublistView(dk, 0, 32), counter, bigEndianCounter: false);
        mac = HmacHasher.sha1(Uint8List.sublistView(dk, 32, 64));
        _out.add(salt);
        _out.add(dk, 64, 66);
        csize += 18;
      }

      RawDeflater? deflater;
      if (actualMethod == 8) {
        deflater = RawDeflater(level, (Uint8List o) => emitPacked(o, 0, o.length));
      }
      produce((Uint8List b, int s, int e) {
        final Uint8List view = Uint8List.sublistView(b, s, e);
        crc.add(view);
        usize += e - s;
        if (deflater != null) {
          deflater.add(b, s, e);
        } else {
          emitPacked(b, s, e);
        }
      });
      deflater?.close();
      if (aes) {
        final Uint8List tag = mac!.close();
        _out.add(tag, 0, 10);
        csize += 10;
      }
    }

    final int crcValue = aes ? 0 : crc.value;
    final ByteBuilder patch = ByteBuilder(16);
    if (zip64) {
      patch.addU32le(crcValue);
      _out.patch(headerPos + 14, patch.toBytes());
      final ByteBuilder p64 = ByteBuilder(16);
      p64.addU64le(usize);
      p64.addU64le(csize);
      _out.patch(headerPos + 30 + nameBytes.length + 4, p64.toBytes());
      assert(zip64Pos == 4);
    } else {
      if (csize >= 0xFFFFFFFF || usize >= 0xFFFFFFFF) {
        throw const PzException('A file grew beyond 4 GiB while it was being added.');
      }
      patch.addU32le(crcValue);
      patch.addU32le(csize);
      patch.addU32le(usize);
      _out.patch(headerPos + 14, patch.toBytes());
    }

    final bool bigOffset = headerPos >= 0xFFFFFFFF;
    final ByteBuilder cx = ByteBuilder(64);
    if (zip64 || bigOffset) {
      cx.addU16le(0x0001);
      cx.addU16le((zip64 ? 16 : 0) + (bigOffset ? 8 : 0));
      if (zip64) {
        cx.addU64le(usize);
        cx.addU64le(csize);
      }
      if (bigOffset) cx.addU64le(headerPos);
    }
    cx.addU16le(0x5455);
    cx.addU16le(5);
    cx.addByte(1);
    cx.addU32le(unixTime);
    if (aes) {
      cx.addU16le(0x9901);
      cx.addU16le(7);
      cx.addU16le(2);
      cx.addByte(0x41);
      cx.addByte(0x45);
      cx.addByte(3);
      cx.addU16le(actualMethod);
    }
    final Uint8List cxb = cx.toBytes();
    _cd.addU32le(0x02014b50);
    _cd.addU16le((3 << 8) | 63);
    _cd.addU16le(zip64 || bigOffset ? 45 : needed);
    _cd.addU16le(flags);
    _cd.addU16le(method);
    _cd.addU16le(_dosTime(mod));
    _cd.addU16le(_dosDate(mod));
    _cd.addU32le(crcValue);
    _cd.addU32le(zip64 ? 0xFFFFFFFF : csize);
    _cd.addU32le(zip64 ? 0xFFFFFFFF : usize);
    _cd.addU16le(nameBytes.length);
    _cd.addU16le(cxb.length);
    _cd.addU16le(0);
    _cd.addU16le(0);
    _cd.addU16le(0);
    _cd.addU32le(extAttr);
    _cd.addU32le(bigOffset ? 0xFFFFFFFF : headerPos);
    _cd.addBytes(nameBytes);
    _cd.addBytes(cxb);
    _count++;
  }

  @override
  void finishFormat() {
    final int cdPos = _out.position;
    final int cdSize = _cd.length;
    _out.add(_cd.view());
    final bool big = _count >= 0xFFFF || cdPos >= 0xFFFFFFFF || cdSize >= 0xFFFFFFFF;
    if (big) {
      final int e64 = _out.position;
      final ByteBuilder z = ByteBuilder(128);
      z.addU32le(0x06064b50);
      z.addU64le(44);
      z.addU16le((3 << 8) | 63);
      z.addU16le(45);
      z.addU32le(0);
      z.addU32le(0);
      z.addU64le(_count);
      z.addU64le(_count);
      z.addU64le(cdSize);
      z.addU64le(cdPos);
      z.addU32le(0x07064b50);
      z.addU32le(0);
      z.addU64le(e64);
      z.addU32le(1);
      _out.add(z.view());
    }
    final ByteBuilder e = ByteBuilder(32);
    e.addU32le(0x06054b50);
    e.addU16le(0);
    e.addU16le(0);
    e.addU16le(big ? 0xFFFF : _count);
    e.addU16le(big ? 0xFFFF : _count);
    e.addU32le(big ? 0xFFFFFFFF : cdSize);
    e.addU32le(big ? 0xFFFFFFFF : cdPos);
    e.addU16le(0);
    _out.add(e.view());
    _out.close();
  }

  @override
  void closeRaw() {
    try {
      _out.close();
    } catch (_) {}
  }
}
