import 'dart:io';
import 'dart:typed_data';

import 'errors.dart';
import 'hash.dart';
import 'io.dart';
import 'lzma.dart';
import 'lzma_enc.dart';

const int _crc64Poly = 0xC96C5795D7870F42;

final Int64List _crc64Table = _makeCrc64Table();

Int64List _makeCrc64Table() {
  final Int64List t = Int64List(256);
  for (var n = 0; n < 256; n++) {
    var c = n;
    for (var k = 0; k < 8; k++) {
      c = (c & 1) != 0 ? ((c >>> 1) ^ _crc64Poly) : (c >>> 1);
    }
    t[n] = c;
  }
  return t;
}

class Crc64 {
  int _c = -1;

  void add(List<int> chunk) {
    var c = _c;
    final int n = chunk.length;
    for (var i = 0; i < n; i++) {
      c = _crc64Table[(c ^ chunk[i]) & 0xFF] ^ (c >>> 8);
    }
    _c = c;
  }

  Uint8List digest() {
    final int v = ~_c;
    final Uint8List out = Uint8List(8);
    for (var i = 0; i < 8; i++) {
      out[i] = (v >>> (8 * i)) & 0xFF;
    }
    return out;
  }
}

int _vli(ByteInput input) {
  var r = 0;
  var shift = 0;
  for (var i = 0; i < 9; i++) {
    final int b = input.readByte();
    r |= (b & 0x7F) << shift;
    shift += 7;
    if ((b & 0x80) == 0) return r;
  }
  throw const PzCorrupt('Bad xz data.');
}

Uint8List _le32(int v) =>
    Uint8List.fromList(<int>[v & 255, (v >> 8) & 255, (v >> 16) & 255, (v >> 24) & 255]);

int xzDecode(ByteInput input, ChunkSink sink, {CancelToken? cancel}) {
  var total = 0;
  var first = true;
  while (true) {
    if (!first) {
      while (input.peek() == 0) {
        input.readByte();
      }
      if (input.peek() < 0) break;
    }
    first = false;
    final Uint8List hdr = input.readExact(12);
    const List<int> magic = <int>[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00];
    for (var i = 0; i < 6; i++) {
      if (hdr[i] != magic[i]) throw const PzCorrupt('This is not an xz file.');
    }
    final int crcStored = hdr[8] | (hdr[9] << 8) | (hdr[10] << 16) | (hdr[11] << 24);
    if (crc32(hdr, 6, 8) != crcStored) throw const PzCorrupt('Bad xz header.');
    final int check = hdr[7] & 15;
    final int checkSize = check == 0 ? 0 : 4 * (1 << ((check - 1) ~/ 3));
    while (true) {
      if (cancel != null && cancel.isCancelled) throw const PzCancelled();
      final int b = input.readByte();
      if (b == 0) {
        final int count = _vli(input);
        var idxUsed = 1 + _vliLen(count);
        for (var i = 0; i < count; i++) {
          final int u = _vli(input);
          final int s = _vli(input);
          idxUsed += _vliLen(u) + _vliLen(s);
        }
        input.skip((4 - idxUsed % 4) % 4);
        input.skip(4);
        input.skip(12);
        break;
      }
      final int hsize = (b + 1) * 4;
      final Uint8List rest = input.readExact(hsize - 1);
      final Uint8List h = Uint8List(hsize)..[0] = b;
      h.setRange(1, hsize, rest);
      final int hcrc = h[hsize - 4] | (h[hsize - 3] << 8) | (h[hsize - 2] << 16) | (h[hsize - 1] << 24);
      if (crc32(h, 0, hsize - 4) != hcrc) throw const PzCorrupt('Bad xz block header.');
      final int fl = h[1];
      final BytesInput hs = BytesInput(h, 2, hsize - 4);
      if ((fl & 0x40) != 0) _vli(hs);
      int? usize;
      if ((fl & 0x80) != 0) usize = _vli(hs);
      if ((fl & 3) != 0) throw const PzUnsupported('This xz file uses filters pzip cannot read.');
      final int fid = _vli(hs);
      final int psz = _vli(hs);
      if (fid != 0x21 || psz != 1) {
        throw const PzUnsupported('This xz file uses filters pzip cannot read.');
      }
      final int dictByte = hs.readByte();
      Crc32? c32;
      Crc64? c64;
      Hasher? sha;
      if (check == 1) {
        c32 = Crc32();
      } else if (check == 4) {
        c64 = Crc64();
      } else if (check == 10) {
        sha = sha256Hasher();
      }
      final int start = input.position;
      var produced = 0;
      lzma2Decode(input, dictByte, (Uint8List buf, int s, int e) {
        final Uint8List v = Uint8List.sublistView(buf, s, e);
        c32?.add(v);
        c64?.add(v);
        sha?.add(v);
        produced += e - s;
        sink(buf, s, e);
      }, cap: usize, cancel: cancel);
      final int used = input.position - start;
      input.skip((4 - used % 4) % 4);
      if (checkSize > 0) {
        final Uint8List stored = input.readExact(checkSize);
        Uint8List? calc;
        if (c32 != null) calc = _le32(c32.value);
        if (c64 != null) calc = c64.digest();
        if (sha != null) calc = sha.close();
        if (calc != null && !constantTimeEquals(calc, stored)) {
          throw const PzCorrupt('The xz data is damaged (bad checksum).');
        }
      }
      if (usize != null && usize != produced) {
        throw const PzCorrupt('The xz data has the wrong size.');
      }
      total += produced;
    }
  }
  return total;
}

int _vliLen(int v) {
  var n = 1;
  while (v >= 0x80) {
    v >>= 7;
    n++;
  }
  return n;
}

int xzUncompressedSize(RandomAccessFile raf, int len) {
  try {
    if (len < 32) return -1;
    raf.setPositionSync(len - 12);
    final Uint8List f = Uint8List(12);
    raf.readIntoSync(f, 0, 12);
    if (f[10] != 0x59 || f[11] != 0x5A) return -1;
    final int back = (f[4] | (f[5] << 8) | (f[6] << 16) | (f[7] << 24)) + 1;
    final int idxLen = back * 4;
    final int pos = len - 12 - idxLen;
    if (pos < 12) return -1;
    final FileInput idx = FileInput(raf, pos, len - 12);
    if (idx.readByte() != 0) return -1;
    final int count = _vli(idx);
    var total = 0;
    for (var i = 0; i < count; i++) {
      _vli(idx);
      total += _vli(idx);
    }
    return total;
  } catch (_) {
    return -1;
  }
}

int _vliPut(ByteBuilder b, int n) {
  var c = 1;
  while (n >= 0x80) {
    b.addByte((n & 0x7F) | 0x80);
    n >>= 7;
    c++;
  }
  b.addByte(n);
  return c;
}

class XzSink extends DataSink {
  XzSink(this._out, int level) {
    final Uint8List flags = Uint8List.fromList(<int>[0, 1]);
    _out.add(<int>[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]);
    _out.add(flags);
    final ByteBuilder c = ByteBuilder(4);
    c.addU32le(crc32(flags));
    _out.add(c.view());
    _enc = Lzma2Encoder(level, (Uint8List b, int s, int e) {
      _comp += e - s;
      _out.add(b, s, e);
    });
    final Uint8List bh = Uint8List.fromList(<int>[2, 0, 0x21, 1, _enc.dictProp, 0, 0, 0]);
    _out.add(bh);
    final ByteBuilder bc = ByteBuilder(4);
    bc.addU32le(crc32(bh));
    _out.add(bc.view());
  }

  final BufferedOut _out;
  late final Lzma2Encoder _enc;
  final Crc32 _crc = Crc32();
  int _comp = 0;
  int _size = 0;

  @override
  void add(Uint8List buf, int start, int end) {
    _crc.add(Uint8List.sublistView(buf, start, end));
    _size += end - start;
    _enc.add(buf, start, end);
  }

  @override
  void close() {
    _enc.finish();
    final int pad = (4 - _comp % 4) % 4;
    if (pad > 0) _out.add(Uint8List(pad));
    final ByteBuilder chk = ByteBuilder(4);
    chk.addU32le(_crc.value);
    _out.add(chk.view());
    final ByteBuilder idx = ByteBuilder(32);
    idx.addByte(0);
    _vliPut(idx, 1);
    _vliPut(idx, 12 + _comp + 4);
    _vliPut(idx, _size);
    while (idx.length % 4 != 0) {
      idx.addByte(0);
    }
    final int icrc = crc32(idx.view());
    idx.addU32le(icrc);
    _out.add(idx.view());
    final ByteBuilder back = ByteBuilder(8);
    back.addU32le(idx.length ~/ 4 - 1);
    back.addByte(0);
    back.addByte(1);
    final ByteBuilder foot = ByteBuilder(12);
    foot.addU32le(crc32(back.view()));
    foot.addBytes(back.view());
    foot.addByte(0x59);
    foot.addByte(0x5A);
    _out.add(foot.view());
    _out.close();
  }

  @override
  void closeRaw() {
    try {
      _out.close();
    } catch (_) {}
  }
}
