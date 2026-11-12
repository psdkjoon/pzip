import 'dart:math';
import 'dart:typed_data';

import 'consts.dart';

/// A hash that takes its data in pieces.
///
/// Call [add] any number of times, then [close] once for the digest.
abstract class Hasher {
  /// Feeds the next piece of data.
  void add(List<int> chunk);

  /// Finishes the hash and returns the digest. The hasher cannot be used again.
  Uint8List close();
}

const int _m32 = 0xFFFFFFFF;

int _rotl(int x, int n) => ((x << n) | (x >> (32 - n))) & _m32;

int _rotr(int x, int n) => ((x >> n) | (x << (32 - n))) & _m32;

Uint8List _asBytes(List<int> data) =>
    data is Uint8List ? data : Uint8List.fromList(data);

abstract class _BlockHasher implements Hasher {
  final Uint8List _buf = Uint8List(64);
  int _bufLen = 0;
  int _total = 0;
  bool _closed = false;

  bool get _littleEndianLength => false;

  void _block(Uint8List b, int o);

  Uint8List _digest();

  _BlockHasher _copy();

  void _copyBase(_BlockHasher to) {
    to._buf.setRange(0, 64, _buf);
    to._bufLen = _bufLen;
    to._total = _total;
  }

  @override
  void add(List<int> chunk) {
    if (_closed) throw StateError('Hasher is closed');
    final Uint8List bytes = _asBytes(chunk);
    _total += bytes.length;
    _feed(bytes);
  }

  void _feed(Uint8List bytes) {
    var i = 0;
    final int n = bytes.length;
    if (_bufLen > 0) {
      while (i < n && _bufLen < 64) {
        _buf[_bufLen++] = bytes[i++];
      }
      if (_bufLen == 64) {
        _block(_buf, 0);
        _bufLen = 0;
      }
    }
    while (i + 64 <= n) {
      _block(bytes, i);
      i += 64;
    }
    while (i < n) {
      _buf[_bufLen++] = bytes[i++];
    }
  }

  @override
  Uint8List close() {
    if (_closed) throw StateError('Hasher is closed');
    final int bits = _total * 8;
    final int padLen = _bufLen < 56 ? 56 - _bufLen : 120 - _bufLen;
    final Uint8List pad = Uint8List(padLen + 8);
    pad[0] = 0x80;
    for (var k = 0; k < 8; k++) {
      final int shift = _littleEndianLength ? 8 * k : 56 - 8 * k;
      pad[padLen + k] = (bits >> shift) & 0xFF;
    }
    _feed(pad);
    _closed = true;
    return _digest();
  }
}

class _Sha256 extends _BlockHasher {
  _Sha256() : _h = Uint32List.fromList(sha256H0);

  _Sha256._copyOf(this._h);

  final Uint32List _h;
  static final Uint32List _w = Uint32List(64);

  @override
  _BlockHasher _copy() {
    final _Sha256 c = _Sha256._copyOf(Uint32List.fromList(_h));
    _copyBase(c);
    return c;
  }

  @override
  void _block(Uint8List b, int o) {
    final Uint32List w = _w;
    for (var t = 0; t < 16; t++) {
      final int j = o + t * 4;
      w[t] = (b[j] << 24) | (b[j + 1] << 16) | (b[j + 2] << 8) | b[j + 3];
    }
    for (var t = 16; t < 64; t++) {
      final int x = w[t - 15];
      final int y = w[t - 2];
      final int s0 = _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3);
      final int s1 = _rotr(y, 17) ^ _rotr(y, 19) ^ (y >> 10);
      w[t] = (w[t - 16] + s0 + w[t - 7] + s1) & _m32;
    }
    int a = _h[0], b2 = _h[1], c = _h[2], d = _h[3];
    int e = _h[4], f = _h[5], g = _h[6], h = _h[7];
    for (var t = 0; t < 64; t++) {
      final int s1 = _rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25);
      final int ch = (e & f) ^ ((~e & _m32) & g);
      final int t1 = (h + s1 + ch + sha256K[t] + w[t]) & _m32;
      final int s0 = _rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22);
      final int maj = (a & b2) ^ (a & c) ^ (b2 & c);
      final int t2 = (s0 + maj) & _m32;
      h = g;
      g = f;
      f = e;
      e = (d + t1) & _m32;
      d = c;
      c = b2;
      b2 = a;
      a = (t1 + t2) & _m32;
    }
    _h[0] = (_h[0] + a) & _m32;
    _h[1] = (_h[1] + b2) & _m32;
    _h[2] = (_h[2] + c) & _m32;
    _h[3] = (_h[3] + d) & _m32;
    _h[4] = (_h[4] + e) & _m32;
    _h[5] = (_h[5] + f) & _m32;
    _h[6] = (_h[6] + g) & _m32;
    _h[7] = (_h[7] + h) & _m32;
  }

  @override
  Uint8List _digest() {
    final Uint8List out = Uint8List(32);
    for (var i = 0; i < 8; i++) {
      out[i * 4] = (_h[i] >> 24) & 0xFF;
      out[i * 4 + 1] = (_h[i] >> 16) & 0xFF;
      out[i * 4 + 2] = (_h[i] >> 8) & 0xFF;
      out[i * 4 + 3] = _h[i] & 0xFF;
    }
    return out;
  }
}

class _Sha1 extends _BlockHasher {
  _Sha1()
      : _h = Uint32List.fromList(
            <int>[0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]);

  _Sha1._copyOf(this._h);

  final Uint32List _h;
  static final Uint32List _w = Uint32List(80);

  @override
  _BlockHasher _copy() {
    final _Sha1 c = _Sha1._copyOf(Uint32List.fromList(_h));
    _copyBase(c);
    return c;
  }

  @override
  void _block(Uint8List b, int o) {
    final Uint32List w = _w;
    for (var t = 0; t < 16; t++) {
      final int j = o + t * 4;
      w[t] = (b[j] << 24) | (b[j + 1] << 16) | (b[j + 2] << 8) | b[j + 3];
    }
    for (var t = 16; t < 80; t++) {
      w[t] = _rotl(w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16], 1);
    }
    int a = _h[0], b2 = _h[1], c = _h[2], d = _h[3], e = _h[4];
    for (var t = 0; t < 80; t++) {
      int f;
      int k;
      if (t < 20) {
        f = (b2 & c) | ((~b2 & _m32) & d);
        k = 0x5A827999;
      } else if (t < 40) {
        f = b2 ^ c ^ d;
        k = 0x6ED9EBA1;
      } else if (t < 60) {
        f = (b2 & c) | (b2 & d) | (c & d);
        k = 0x8F1BBCDC;
      } else {
        f = b2 ^ c ^ d;
        k = 0xCA62C1D6;
      }
      final int temp = (_rotl(a, 5) + f + e + k + w[t]) & _m32;
      e = d;
      d = c;
      c = _rotl(b2, 30);
      b2 = a;
      a = temp;
    }
    _h[0] = (_h[0] + a) & _m32;
    _h[1] = (_h[1] + b2) & _m32;
    _h[2] = (_h[2] + c) & _m32;
    _h[3] = (_h[3] + d) & _m32;
    _h[4] = (_h[4] + e) & _m32;
  }

  @override
  Uint8List _digest() {
    final Uint8List out = Uint8List(20);
    for (var i = 0; i < 5; i++) {
      out[i * 4] = (_h[i] >> 24) & 0xFF;
      out[i * 4 + 1] = (_h[i] >> 16) & 0xFF;
      out[i * 4 + 2] = (_h[i] >> 8) & 0xFF;
      out[i * 4 + 3] = _h[i] & 0xFF;
    }
    return out;
  }
}

class _Md5 extends _BlockHasher {
  _Md5()
      : _h = Uint32List.fromList(
            <int>[0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476]);

  _Md5._copyOf(this._h);

  final Uint32List _h;
  static final Uint32List _w = Uint32List(16);

  @override
  bool get _littleEndianLength => true;

  @override
  _BlockHasher _copy() {
    final _Md5 c = _Md5._copyOf(Uint32List.fromList(_h));
    _copyBase(c);
    return c;
  }

  @override
  void _block(Uint8List b, int o) {
    final Uint32List w = _w;
    for (var t = 0; t < 16; t++) {
      final int j = o + t * 4;
      w[t] = b[j] | (b[j + 1] << 8) | (b[j + 2] << 16) | (b[j + 3] << 24);
    }
    int a = _h[0], b2 = _h[1], c = _h[2], d = _h[3];
    for (var i = 0; i < 64; i++) {
      int f;
      int g;
      if (i < 16) {
        f = (b2 & c) | ((~b2 & _m32) & d);
        g = i;
      } else if (i < 32) {
        f = (d & b2) | ((~d & _m32) & c);
        g = (5 * i + 1) & 15;
      } else if (i < 48) {
        f = b2 ^ c ^ d;
        g = (3 * i + 5) & 15;
      } else {
        f = c ^ (b2 | (~d & _m32));
        g = (7 * i) & 15;
      }
      f = (f + a + md5K[i] + w[g]) & _m32;
      a = d;
      d = c;
      c = b2;
      b2 = (b2 + _rotl(f, md5Shifts[i])) & _m32;
    }
    _h[0] = (_h[0] + a) & _m32;
    _h[1] = (_h[1] + b2) & _m32;
    _h[2] = (_h[2] + c) & _m32;
    _h[3] = (_h[3] + d) & _m32;
  }

  @override
  Uint8List _digest() {
    final Uint8List out = Uint8List(16);
    for (var i = 0; i < 4; i++) {
      out[i * 4] = _h[i] & 0xFF;
      out[i * 4 + 1] = (_h[i] >> 8) & 0xFF;
      out[i * 4 + 2] = (_h[i] >> 16) & 0xFF;
      out[i * 4 + 3] = (_h[i] >> 24) & 0xFF;
    }
    return out;
  }
}

/// A new SHA-1 hasher (20-byte digest).
Hasher sha1Hasher() => _Sha1();

/// A new SHA-256 hasher (32-byte digest).
Hasher sha256Hasher() => _Sha256();

/// A new MD5 hasher (16-byte digest).
Hasher md5Hasher() => _Md5();

/// The SHA-1 digest of [data].
Uint8List sha1(List<int> data) => (_Sha1()..add(data)).close();

/// The SHA-256 digest of [data].
Uint8List sha256(List<int> data) => (_Sha256()..add(data)).close();

/// The MD5 digest of [data].
Uint8List md5(List<int> data) => (_Md5()..add(data)).close();

final Uint32List _crcTable = _makeCrcTable();

/// The 256-entry CRC-32 lookup table (polynomial `0xEDB88320`).
Uint32List get crc32Table => _crcTable;

Uint32List _makeCrcTable() {
  final Uint32List t = Uint32List(256);
  for (var n = 0; n < 256; n++) {
    var c = n;
    for (var k = 0; k < 8; k++) {
      c = (c & 1) != 0 ? (0xEDB88320 ^ (c >> 1)) : (c >> 1);
    }
    t[n] = c;
  }
  return t;
}

/// The CRC-32 of `data[start..end)`. [end] defaults to the length of [data].
int crc32(List<int> data, [int start = 0, int? end]) {
  final int stop = end ?? data.length;
  var c = 0xFFFFFFFF;
  for (var i = start; i < stop; i++) {
    c = _crcTable[(c ^ data[i]) & 0xFF] ^ (c >> 8);
  }
  return (c ^ 0xFFFFFFFF) & _m32;
}

/// A CRC-32 computed in pieces: call [add] for each piece, then read [value].
class Crc32 {
  int _c = 0xFFFFFFFF;

  /// Feeds the next piece of data.
  void add(List<int> chunk) {
    var c = _c;
    final int n = chunk.length;
    for (var i = 0; i < n; i++) {
      c = _crcTable[(c ^ chunk[i]) & 0xFF] ^ (c >> 8);
    }
    _c = c;
  }

  /// The CRC-32 of everything added so far.
  int get value => (_c ^ 0xFFFFFFFF) & _m32;
}

/// [bytes] as lower-case hexadecimal text, two digits per byte.
String toHexString(List<int> bytes) {
  final StringBuffer b = StringBuffer();
  for (final int v in bytes) {
    b.write(v.toRadixString(16).padLeft(2, '0'));
  }
  return b.toString();
}

class _Hmac {
  _Hmac(_BlockHasher Function() make, List<int> key) {
    Uint8List k = _asBytes(key);
    if (k.length > 64) {
      final _BlockHasher h = make();
      h.add(k);
      k = h.close();
    }
    final Uint8List ipad = Uint8List(64);
    final Uint8List opad = Uint8List(64);
    for (var i = 0; i < 64; i++) {
      final int v = i < k.length ? k[i] : 0;
      ipad[i] = v ^ 0x36;
      opad[i] = v ^ 0x5C;
    }
    _inner = make()..add(ipad);
    _outer = make()..add(opad);
  }

  late final _BlockHasher _inner;
  late final _BlockHasher _outer;

  Uint8List mac(Uint8List data) {
    final _BlockHasher i = _inner._copy();
    i.add(data);
    final Uint8List ih = i.close();
    final _BlockHasher o = _outer._copy();
    o.add(ih);
    return o.close();
  }

  Uint8List mac2(Uint8List a, Uint8List b) {
    final _BlockHasher i = _inner._copy();
    i.add(a);
    i.add(b);
    final Uint8List ih = i.close();
    final _BlockHasher o = _outer._copy();
    o.add(ih);
    return o.close();
  }
}

/// HMAC fed in pieces: call [add] any number of times, then [close] for the
/// tag.
class HmacHasher {
  /// HMAC-SHA-1 with [key].
  HmacHasher.sha1(List<int> key) : this._(_Hmac(() => _Sha1(), key));

  /// HMAC-SHA-256 with [key].
  HmacHasher.sha256(List<int> key) : this._(_Hmac(() => _Sha256(), key));

  HmacHasher._(_Hmac h)
      : _inner = h._inner._copy(),
        _outer = h._outer._copy();

  final _BlockHasher _inner;
  final _BlockHasher _outer;

  /// Feeds the next piece of data.
  void add(List<int> chunk) => _inner.add(chunk);

  /// Finishes and returns the tag. The object cannot be used again.
  Uint8List close() {
    _outer.add(_inner.close());
    return _outer.close();
  }
}

/// The HMAC-SHA-1 tag of [data] under [key].
Uint8List hmacSha1(List<int> key, List<int> data) =>
    _Hmac(() => _Sha1(), key).mac(_asBytes(data));

/// The HMAC-SHA-256 tag of [data] under [key].
Uint8List hmacSha256(List<int> key, List<int> data) =>
    _Hmac(() => _Sha256(), key).mac(_asBytes(data));

Uint8List _pbkdf2(_BlockHasher Function() make, int hashLen, List<int> password,
    List<int> salt, int iterations, int length) {
  final _Hmac hmac = _Hmac(make, password);
  final Uint8List saltBytes = _asBytes(salt);
  final Uint8List out = Uint8List(length);
  final int blocks = (length + hashLen - 1) ~/ hashLen;
  for (var block = 1; block <= blocks; block++) {
    final Uint8List counter = Uint8List(4);
    counter[0] = (block >> 24) & 0xFF;
    counter[1] = (block >> 16) & 0xFF;
    counter[2] = (block >> 8) & 0xFF;
    counter[3] = block & 0xFF;
    Uint8List u = hmac.mac2(saltBytes, counter);
    final Uint8List t = Uint8List.fromList(u);
    for (var i = 1; i < iterations; i++) {
      u = hmac.mac(u);
      for (var j = 0; j < hashLen; j++) {
        t[j] ^= u[j];
      }
    }
    final int offset = (block - 1) * hashLen;
    final int take = min(hashLen, length - offset);
    out.setRange(offset, offset + take, t);
  }
  return out;
}

/// PBKDF2 with HMAC-SHA-1: derives [length] bytes from [password] and [salt]
/// with [iterations] rounds.
Uint8List pbkdf2HmacSha1(
  List<int> password,
  List<int> salt,
  int iterations,
  int length,
) =>
    _pbkdf2(() => _Sha1(), 20, password, salt, iterations, length);

/// PBKDF2 with HMAC-SHA-256: derives [length] bytes from [password] and [salt]
/// with [iterations] rounds.
Uint8List pbkdf2HmacSha256(
  List<int> password,
  List<int> salt,
  int iterations,
  int length,
) =>
    _pbkdf2(() => _Sha256(), 32, password, salt, iterations, length);

/// [length] cryptographically secure random bytes.
Uint8List randomBytes(int length) {
  final Random r = Random.secure();
  final Uint8List out = Uint8List(length);
  for (var i = 0; i < length; i++) {
    out[i] = r.nextInt(256);
  }
  return out;
}

/// Compares two byte lists in time that does not depend on where they differ.
bool constantTimeEquals(List<int> a, List<int> b) {
  if (a.length != b.length) return false;
  var diff = 0;
  for (var i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff == 0;
}
