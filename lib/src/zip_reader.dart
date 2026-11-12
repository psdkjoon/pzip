import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'aes.dart';
import 'api.dart';
import 'deflate.dart';
import 'errors.dart';
import 'hash.dart';
import 'io.dart';
import 'reader_base.dart';

class _AesInfo {
  _AesInfo(this.version, this.strength, this.method);

  final int version;
  final int strength;
  final int method;

  int get keyLen => strength == 1 ? 16 : (strength == 2 ? 24 : 32);

  int get saltLen => strength == 1 ? 8 : (strength == 2 ? 12 : 16);
}

class _ZipInfo {
  _ZipInfo({
    required this.method,
    required this.flags,
    required this.crc,
    required this.csize,
    required this.size,
    required this.offset,
    required this.dosTime,
    this.aes,
  });

  final int method;
  final int flags;
  final int crc;
  final int csize;
  final int size;
  final int offset;
  final int dosTime;
  final _AesInfo? aes;

  bool get encrypted => (flags & 1) != 0;
}

class _ZipCryptoInput extends ByteInput {
  _ZipCryptoInput(this._in, List<int> password) {
    for (final int c in password) {
      _update(c);
    }
  }

  final ByteInput _in;
  int _k0 = 0x12345678;
  int _k1 = 0x23456789;
  int _k2 = 0x34567890;

  void _update(int c) {
    final Uint32List t = crc32Table;
    _k0 = t[(_k0 ^ c) & 0xFF] ^ (_k0 >> 8);
    _k1 = ((_k1 + (_k0 & 0xFF)) * 134775813 + 1) & 0xFFFFFFFF;
    _k2 = t[(_k2 ^ (_k1 >> 24)) & 0xFF] ^ (_k2 >> 8);
  }

  int _dec(int c) {
    final int t = (_k2 | 2) & 0xFFFF;
    final int p = (c ^ (((t * (t ^ 1)) >> 8) & 0xFF)) & 0xFF;
    _update(p);
    return p;
  }

  int readHeader() {
    var last = 0;
    for (var i = 0; i < 12; i++) {
      last = _dec(_in.readByte());
    }
    return last;
  }

  @override
  int get position => _in.position;

  @override
  int readByte() => _dec(_in.readByte());

  @override
  int read(Uint8List buf, int off, int len) {
    final int n = _in.read(buf, off, len);
    for (var i = off; i < off + n; i++) {
      buf[i] = _dec(buf[i]);
    }
    return n;
  }

  @override
  void skip(int n) {
    for (var i = 0; i < n; i++) {
      readByte();
    }
  }
}

class _AesInput extends ByteInput {
  _AesInput(this._in, this._ctr, this._mac, this._remaining);

  final ByteInput _in;
  final AesCtr _ctr;
  final HmacHasher _mac;
  int _remaining;
  int _used = 0;
  final Uint8List _one = Uint8List(1);

  @override
  int get position => _used;

  @override
  int readByte() {
    if (read(_one, 0, 1) <= 0) throw const PzCorrupt('The file ends too early.');
    return _one[0];
  }

  @override
  int read(Uint8List buf, int off, int len) {
    final int want = len < _remaining ? len : _remaining;
    if (want <= 0) return 0;
    final int r = _in.read(buf, off, want);
    if (r <= 0) return 0;
    final Uint8List chunk = Uint8List.sublistView(buf, off, off + r);
    _mac.add(chunk);
    final Uint8List dec = _ctr.process(chunk);
    buf.setRange(off, off + r, dec);
    _remaining -= r;
    _used += r;
    return r;
  }

  @override
  void skip(int n) {
    final Uint8List tmp = Uint8List(n < 4096 ? n : 4096);
    var left = n;
    while (left > 0) {
      final int r = read(tmp, 0, left < tmp.length ? left : tmp.length);
      if (r <= 0) throw const PzCorrupt('The file ends too early.');
      left -= r;
    }
  }

  void verify() {
    final Uint8List tmp = Uint8List(4096);
    while (_remaining > 0) {
      if (read(tmp, 0, tmp.length) <= 0) break;
    }
    final Uint8List stored = _in.readExact(10);
    final Uint8List calc = _mac.close();
    if (!constantTimeEquals(stored, Uint8List.sublistView(calc, 0, 10))) {
      throw const PzCorrupt('The encrypted data is damaged.');
    }
  }
}

class ZipReader extends ReaderBase {
  ZipReader._(super.path, this._raf, this._password);

  final RandomAccessFile _raf;
  final String? _password;
  final List<PzEntry> _entries = <PzEntry>[];
  final Map<PzEntry, _ZipInfo> _info = Map<PzEntry, _ZipInfo>.identity();
  bool _hasEncrypted = false;
  int _length = 0;

  static ZipReader open(String path, String? password) {
    final RandomAccessFile raf = File(path).openSync();
    final ZipReader r = ZipReader._(path, raf, password);
    try {
      r._load();
    } catch (_) {
      raf.closeSync();
      rethrow;
    }
    return r;
  }

  Uint8List _readAt(int pos, int n) {
    _raf.setPositionSync(pos);
    final Uint8List b = Uint8List(n);
    var got = 0;
    while (got < n) {
      final int r = _raf.readIntoSync(b, got, n);
      if (r <= 0) throw const PzCorrupt('The file ends too early.');
      got += r;
    }
    return b;
  }

  void _load() {
    _length = _raf.lengthSync();
    if (_length < 22) throw const PzCorrupt('This is not a zip file.');
    final int tailLen = _length < 65557 ? _length : 65557;
    final int tailStart = _length - tailLen;
    final Uint8List tail = _readAt(tailStart, tailLen);
    final ByteData tb = ByteData.sublistView(tail);
    var found = -1;
    for (var i = tailLen - 22; i >= 0; i--) {
      if (tb.getUint32(i, Endian.little) == 0x06054b50) {
        found = i;
        break;
      }
    }
    if (found < 0) throw const PzCorrupt('This is not a zip file.');
    final int eocdPos = tailStart + found;
    var cdSize = tb.getUint32(found + 12, Endian.little);
    var cdOff = tb.getUint32(found + 16, Endian.little);
    final int total16 = tb.getUint16(found + 10, Endian.little);
    var cdEnd = eocdPos;
    if (total16 == 0xFFFF || cdSize == 0xFFFFFFFF || cdOff == 0xFFFFFFFF) {
      if (eocdPos >= 20) {
        final ByteData loc = ByteData.sublistView(_readAt(eocdPos - 20, 20));
        if (loc.getUint32(0, Endian.little) == 0x07064b50) {
          final int e64 = loc.getUint64(8, Endian.little);
          if (e64 >= 0 && e64 + 56 <= _length) {
            final ByteData z = ByteData.sublistView(_readAt(e64, 56));
            if (z.getUint32(0, Endian.little) == 0x06064b50) {
              cdSize = z.getUint64(40, Endian.little);
              cdOff = z.getUint64(48, Endian.little);
              cdEnd = e64;
            }
          }
        }
      }
    }
    final int delta = cdEnd - cdSize - cdOff;
    if (delta < 0 || cdSize > (1 << 28)) throw const PzCorrupt('The zip index is damaged.');
    final Uint8List cd = _readAt(cdOff + delta, cdSize);
    final ByteData bd = ByteData.sublistView(cd);
    var p = 0;
    while (p + 46 <= cd.length && bd.getUint32(p, Endian.little) == 0x02014b50) {
      final int madeBy = bd.getUint16(p + 4, Endian.little);
      final int flags = bd.getUint16(p + 8, Endian.little);
      var method = bd.getUint16(p + 10, Endian.little);
      final int dosTime = bd.getUint16(p + 12, Endian.little);
      final int dosDate = bd.getUint16(p + 14, Endian.little);
      final int crc = bd.getUint32(p + 16, Endian.little);
      var csize = bd.getUint32(p + 20, Endian.little);
      var usize = bd.getUint32(p + 24, Endian.little);
      final int nameLen = bd.getUint16(p + 28, Endian.little);
      final int extraLen = bd.getUint16(p + 30, Endian.little);
      final int commentLen = bd.getUint16(p + 32, Endian.little);
      final int ext = bd.getUint32(p + 38, Endian.little);
      var offset = bd.getUint32(p + 42, Endian.little);
      final int next = p + 46 + nameLen + extraLen + commentLen;
      if (next > cd.length) throw const PzCorrupt('The zip index is damaged.');
      final Uint8List nameBytes = Uint8List.sublistView(cd, p + 46, p + 46 + nameLen);
      String name;
      try {
        name = utf8.decode(nameBytes);
      } catch (_) {
        name = latin1.decode(nameBytes);
      }
      DateTime? modified = _dosToDate(dosDate, dosTime);
      _AesInfo? aes;
      var q = p + 46 + nameLen;
      final int qEnd = q + extraLen;
      while (q + 4 <= qEnd) {
        final int id = bd.getUint16(q, Endian.little);
        final int sz = bd.getUint16(q + 2, Endian.little);
        final int d = q + 4;
        if (d + sz > qEnd) break;
        if (id == 0x0001) {
          var o = d;
          if (usize == 0xFFFFFFFF && o + 8 <= d + sz) {
            usize = bd.getUint64(o, Endian.little);
            o += 8;
          }
          if (csize == 0xFFFFFFFF && o + 8 <= d + sz) {
            csize = bd.getUint64(o, Endian.little);
            o += 8;
          }
          if (offset == 0xFFFFFFFF && o + 8 <= d + sz) {
            offset = bd.getUint64(o, Endian.little);
          }
        } else if (id == 0x9901 && sz >= 7) {
          aes = _AesInfo(
            bd.getUint16(d, Endian.little),
            bd.getUint8(d + 4),
            bd.getUint16(d + 5, Endian.little),
          );
        } else if (id == 0x5455 && sz >= 5 && (bd.getUint8(d) & 1) != 0) {
          modified = DateTime.fromMillisecondsSinceEpoch(
            bd.getUint32(d + 1, Endian.little) * 1000,
          );
        }
        q = d + sz;
      }
      var storedMethod = method;
      if (method == 99) {
        if (aes == null) throw const PzCorrupt('The zip index is damaged.');
        method = aes.method;
      }
      final int host = madeBy >> 8;
      final int? mode = host == 3 ? (ext >> 16) & 0xFFFF : null;
      final int type = mode == null ? 0 : mode & 0xF000;
      var rel = name.replaceAll('\\', '/');
      final bool slashDir = rel.endsWith('/');
      while (rel.startsWith('/')) {
        rel = rel.substring(1);
      }
      while (rel.endsWith('/')) {
        rel = rel.substring(0, rel.length - 1);
      }
      final bool isDir = slashDir || type == 0x4000 || (ext & 0x10) != 0 && type == 0;
      p = next;
      if (rel.isEmpty) continue;
      final _ZipInfo info = _ZipInfo(
        method: method,
        flags: flags,
        crc: crc,
        csize: csize,
        size: usize,
        offset: offset + delta,
        dosTime: dosTime,
        aes: aes,
      );
      var packed = csize;
      if (aes != null) packed = csize - aes.saltLen - 2 - 10;
      final PzEntry e = PzEntry(
        path: rel,
        isDir: isDir,
        size: isDir ? 0 : usize,
        packedSize: isDir ? 0 : packed,
        modified: modified,
        mode: mode == null ? null : mode & 0xFFF,
        encrypted: info.encrypted,
        linkTarget: null,
      );
      PzEntry entry = e;
      if (!isDir && type == 0xA000 && !info.encrypted && usize < 4096 && storedMethod != 99) {
        try {
          final ByteBuilder b = ByteBuilder(usize < 16 ? 16 : usize);
          _decodeInfo(info, (Uint8List x, int s, int en) => b.addBytes(x, s, en), null);
          entry = PzEntry(
            path: rel,
            isDir: false,
            size: usize,
            packedSize: packed,
            modified: modified,
            mode: mode == null ? null : mode & 0xFFF,
            encrypted: false,
            linkTarget: utf8.decode(b.view(), allowMalformed: true),
          );
        } catch (_) {
          entry = e;
        }
      }
      if (info.encrypted) _hasEncrypted = true;
      _entries.add(entry);
      _info[entry] = info;
    }
  }

  static DateTime? _dosToDate(int d, int t) {
    final int year = ((d >> 9) & 0x7F) + 1980;
    final int month = (d >> 5) & 15;
    final int day = d & 31;
    if (month == 0 || day == 0) return null;
    return DateTime(year, month, day, (t >> 11) & 31, (t >> 5) & 63, (t & 31) * 2);
  }

  @override
  ArchiveFormat get format => ArchiveFormat.zip;

  @override
  List<PzEntry> get entries => _entries;

  @override
  bool get hasEncryptedEntries => _hasEncrypted;

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
    final _ZipInfo? info = _info[entry];
    if (info == null) throw const PzException('Not an entry of this archive.');
    _decodeInfo(info, sink, cancel);
  }

  void _decodeInfo(_ZipInfo info, ChunkSink sink, CancelToken? cancel) {
    if (info.method != 0 && info.method != 8) {
      throw PzUnsupported('Zip method ${info.method} is not supported.');
    }
    final Uint8List h = _readAt(info.offset, 30);
    final ByteData hb = ByteData.sublistView(h);
    if (hb.getUint32(0, Endian.little) != 0x04034b50) {
      throw const PzCorrupt('The zip entry is damaged.');
    }
    final int nl = hb.getUint16(26, Endian.little);
    final int xl = hb.getUint16(28, Endian.little);
    final int dataStart = info.offset + 30 + nl + xl;
    if (dataStart + info.csize > _length) throw const PzCorrupt('The file ends too early.');
    final ByteInput base = FileInput(_raf, dataStart, dataStart + info.csize);
    ByteInput input = base;
    var packed = info.csize;
    _AesInput? aesIn;
    if (info.encrypted) {
      if (_password == null) throw const PzPasswordRequired();
      final Uint8List pw = Uint8List.fromList(utf8.encode(_password));
      final _AesInfo? a = info.aes;
      if (a != null) {
        final Uint8List salt = base.readExact(a.saltLen);
        final Uint8List pwv = base.readExact(2);
        final int kl = a.keyLen;
        final Uint8List dk = pbkdf2HmacSha1(pw, salt, 1000, 2 * kl + 2);
        if (dk[2 * kl] != pwv[0] || dk[2 * kl + 1] != pwv[1]) {
          throw const PzWrongPassword();
        }
        packed = info.csize - a.saltLen - 2 - 10;
        if (packed < 0) throw const PzCorrupt('The zip entry is damaged.');
        final Uint8List counter = Uint8List(16)..[0] = 1;
        aesIn = _AesInput(
          base,
          AesCtr(Uint8List.sublistView(dk, 0, kl), counter, bigEndianCounter: false),
          HmacHasher.sha1(Uint8List.sublistView(dk, kl, 2 * kl)),
          packed,
        );
        input = aesIn;
      } else {
        final _ZipCryptoInput zc = _ZipCryptoInput(base, pw);
        final int last = zc.readHeader();
        final int expect = (info.flags & 8) != 0 ? (info.dosTime >> 8) & 0xFF : (info.crc >> 24) & 0xFF;
        if (last != expect) throw const PzWrongPassword();
        packed = info.csize - 12;
        if (packed < 0) throw const PzCorrupt('The zip entry is damaged.');
        input = zc;
      }
    }
    final Crc32 crc = Crc32();
    var produced = 0;
    void out(Uint8List b, int s, int e) {
      crc.add(Uint8List.sublistView(b, s, e));
      produced += e - s;
      sink(b, s, e);
    }

    if (info.method == 0) {
      final Uint8List buf = Uint8List(65536);
      var left = packed;
      while (left > 0) {
        if (cancel != null && cancel.isCancelled) throw const PzCancelled();
        final int n = input.read(buf, 0, left < buf.length ? left : buf.length);
        if (n <= 0) throw const PzCorrupt('The file ends too early.');
        out(buf, 0, n);
        left -= n;
      }
    } else {
      inflateRaw(input, packed, out, cancel: cancel);
    }
    aesIn?.verify();
    if (produced != info.size) throw const PzCorrupt('The zip entry has the wrong size.');
    final bool crcApplies = info.aes == null || info.aes!.version != 2;
    if (crcApplies && crc.value != info.crc) {
      if (info.encrypted && info.aes == null) throw const PzWrongPassword();
      throw const PzCorrupt('The zip entry is damaged (bad checksum).');
    }
  }
}
