import 'dart:typed_data';

import 'aes.dart';
import 'errors.dart';
import 'hash.dart';
import 'io.dart';

class SzReader {
  SzReader(this.d, [this.p = 0, int? end]) : end = end ?? d.length;

  final Uint8List d;
  int p;
  final int end;

  int byte() {
    if (p >= end) throw const PzCorrupt('The 7z header is damaged.');
    return d[p++];
  }

  Uint8List bytes(int n) {
    if (n < 0 || p + n > end) throw const PzCorrupt('The 7z header is damaged.');
    final Uint8List r = Uint8List.sublistView(d, p, p + n);
    p += n;
    return r;
  }

  void skip(int n) {
    if (n < 0 || p + n > end) throw const PzCorrupt('The 7z header is damaged.');
    p += n;
  }

  int u32() {
    final Uint8List b = bytes(4);
    return b[0] | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
  }

  int u64() {
    final int lo = u32();
    return lo | (u32() << 32);
  }

  int num() {
    final int first = byte();
    var mask = 0x80;
    var val = 0;
    for (var i = 0; i < 8; i++) {
      if ((first & mask) == 0) {
        return val + ((first & (mask - 1)) << (8 * i));
      }
      val |= byte() << (8 * i);
      mask >>= 1;
    }
    return val;
  }

  List<bool> bits(int n) {
    final List<bool> out = List<bool>.filled(n, false);
    var b = 0;
    var m = 0;
    for (var i = 0; i < n; i++) {
      if (m == 0) {
        b = byte();
        m = 0x80;
      }
      out[i] = (b & m) != 0;
      m >>= 1;
    }
    return out;
  }

  List<bool> defined(int n) {
    if (byte() != 0) return List<bool>.filled(n, true);
    return bits(n);
  }

  List<int?> digests(int n) {
    final List<bool> d = defined(n);
    final List<int?> r = List<int?>.filled(n, null);
    for (var i = 0; i < n; i++) {
      if (d[i]) r[i] = u32();
    }
    return r;
  }
}

void szWriteNum(ByteBuilder b, int value) {
  var first = 0;
  var mask = 0x80;
  var i = 0;
  for (; i < 8; i++) {
    if (value < (1 << (7 * (i + 1)))) {
      first |= value >> (8 * i);
      break;
    }
    first |= mask;
    mask >>= 1;
  }
  b.addByte(first);
  for (var k = 0; k < i; k++) {
    b.addByte(value >> (8 * k));
  }
}

Uint8List _utf16le(String s) {
  final Uint8List out = Uint8List(s.length * 2);
  for (var i = 0; i < s.length; i++) {
    final int c = s.codeUnitAt(i);
    out[2 * i] = c & 0xFF;
    out[2 * i + 1] = c >> 8;
  }
  return out;
}

Uint8List sevenZipKey(Uint8List salt, int power, String password) {
  final String cacheKey = '$power/${toHexString(salt)}/$password';
  final Uint8List? hit = _keyCache[cacheKey];
  if (hit != null) return hit;
  final Uint8List pw = _utf16le(password);
  Uint8List key;
  if (power == 0x3F) {
    key = Uint8List(32);
    final Uint8List both = Uint8List(salt.length + pw.length)
      ..setRange(0, salt.length, salt)
      ..setRange(salt.length, salt.length + pw.length, pw);
    key.setRange(0, both.length < 32 ? both.length : 32, both);
  } else {
    if (power > 30) throw const PzUnsupported('The 7z password setting is not supported.');
    final int l = salt.length + pw.length + 8;
    final int rounds = 1 << power;
    var batch = 65536 ~/ l;
    if (batch < 1) batch = 1;
    if (batch > rounds) batch = rounds;
    final Uint8List buf = Uint8List(l * batch);
    for (var j = 0; j < batch; j++) {
      final int off = j * l;
      buf.setRange(off, off + salt.length, salt);
      buf.setRange(off + salt.length, off + salt.length + pw.length, pw);
    }
    final ByteData bd = ByteData.sublistView(buf);
    final Hasher h = sha256Hasher();
    for (var base = 0; base < rounds; base += batch) {
      final int n = (rounds - base) < batch ? (rounds - base) : batch;
      for (var j = 0; j < n; j++) {
        bd.setUint64(j * l + l - 8, base + j, Endian.little);
      }
      h.add(Uint8List.sublistView(buf, 0, n * l));
    }
    key = h.close();
  }
  if (_keyCache.length > 8) _keyCache.clear();
  _keyCache[cacheKey] = key;
  return key;
}

final Map<String, Uint8List> _keyCache = <String, Uint8List>{};

class AesCbcInput extends ByteInput {
  AesCbcInput(this._in, Uint8List key, Uint8List iv, this._limit)
      : _aes = AesBlock(key),
        _prev = Uint8List.fromList(iv);

  final ByteInput _in;
  final AesBlock _aes;
  final int _limit;
  final Uint8List _prev;
  final Uint8List _raw = Uint8List(4096);
  final Uint8List _dec = Uint8List(4096);
  int _decPos = 0;
  int _decLen = 0;
  int _given = 0;

  @override
  int get position => _given;

  bool _fill() {
    var got = 0;
    while (got < _raw.length) {
      final int r = _in.read(_raw, got, _raw.length - got);
      if (r <= 0) break;
      got += r;
    }
    got -= got % 16;
    if (got == 0) return false;
    for (var o = 0; o < got; o += 16) {
      _aes.decrypt(_raw, o, _dec, o);
      for (var i = 0; i < 16; i++) {
        _dec[o + i] ^= o == 0 ? _prev[i] : _raw[o - 16 + i];
      }
    }
    _prev.setRange(0, 16, _raw, got - 16);
    _decPos = 0;
    _decLen = got;
    return true;
  }

  @override
  int peek() {
    if (_given >= _limit) return -1;
    if (_decPos >= _decLen && !_fill()) return -1;
    return _dec[_decPos];
  }

  @override
  int readByte() {
    if (_given >= _limit) throw const PzCorrupt('The file ends too early.');
    if (_decPos >= _decLen && !_fill()) throw const PzCorrupt('The file ends too early.');
    _given++;
    return _dec[_decPos++];
  }

  @override
  int read(Uint8List buf, int off, int len) {
    if (_given >= _limit || len <= 0) return 0;
    if (_decPos >= _decLen && !_fill()) return 0;
    var n = _decLen - _decPos;
    if (n > len) n = len;
    if (n > _limit - _given) n = _limit - _given;
    buf.setRange(off, off + n, _dec, _decPos);
    _decPos += n;
    _given += n;
    return n;
  }

  @override
  void skip(int n) {
    final Uint8List tmp = Uint8List(n < 4096 ? (n < 1 ? 1 : n) : 4096);
    var left = n;
    while (left > 0) {
      final int r = read(tmp, 0, left < tmp.length ? left : tmp.length);
      if (r <= 0) throw const PzCorrupt('The file ends too early.');
      left -= r;
    }
  }
}
