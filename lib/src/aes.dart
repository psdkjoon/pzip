import 'dart:typed_data';

import 'aes_tables.dart';

const int _m32 = 0xFFFFFFFF;

class _AesKey {
  _AesKey(Uint8List key) {
    final int len = key.length;
    if (len != 16 && len != 24 && len != 32) {
      throw ArgumentError('AES key must be 16, 24 or 32 bytes');
    }
    final int nk = len ~/ 4;
    rounds = nk + 6;
    final int total = 4 * (rounds + 1);
    final Uint32List w = Uint32List(total);
    for (var i = 0; i < nk; i++) {
      w[i] = (key[4 * i] << 24) |
          (key[4 * i + 1] << 16) |
          (key[4 * i + 2] << 8) |
          key[4 * i + 3];
    }
    const List<int> rcon = <int>[
      0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36,
    ];
    for (var i = nk; i < total; i++) {
      int t = w[i - 1];
      if (i % nk == 0) {
        t = ((t << 8) | (t >> 24)) & _m32;
        t = _subWord(t) ^ (rcon[i ~/ nk - 1] << 24);
      } else if (nk > 6 && i % nk == 4) {
        t = _subWord(t);
      }
      w[i] = w[i - nk] ^ t;
    }
    enc = w;
    dec = Uint32List.fromList(w);
    for (var r = 1; r < rounds; r++) {
      for (var c = 0; c < 4; c++) {
        final int x = w[4 * r + c];
        dec[4 * r + c] = aesTd0[aesSbox[x >> 24]] ^
            aesTd1[aesSbox[(x >> 16) & 255]] ^
            aesTd2[aesSbox[(x >> 8) & 255]] ^
            aesTd3[aesSbox[x & 255]];
      }
    }
  }

  late final int rounds;
  late final Uint32List enc;
  late final Uint32List dec;

  static int _subWord(int t) =>
      (aesSbox[t >> 24] << 24) |
      (aesSbox[(t >> 16) & 255] << 16) |
      (aesSbox[(t >> 8) & 255] << 8) |
      aesSbox[t & 255];
}

class AesBlock {
  AesBlock(Uint8List key) : _k = _AesKey(key);

  final _AesKey _k;

  void encrypt(Uint8List src, int so, Uint8List dst, int d) {
    final Uint32List w = _k.enc;
    final int rounds = _k.rounds;
    var s0 = ((src[so] << 24) | (src[so + 1] << 16) | (src[so + 2] << 8) | src[so + 3]) ^ w[0];
    var s1 = ((src[so + 4] << 24) | (src[so + 5] << 16) | (src[so + 6] << 8) | src[so + 7]) ^ w[1];
    var s2 = ((src[so + 8] << 24) | (src[so + 9] << 16) | (src[so + 10] << 8) | src[so + 11]) ^ w[2];
    var s3 = ((src[so + 12] << 24) | (src[so + 13] << 16) | (src[so + 14] << 8) | src[so + 15]) ^ w[3];
    for (var r = 1; r < rounds; r++) {
      final int k = 4 * r;
      final int t0 = aesTe0[s0 >> 24] ^ aesTe1[(s1 >> 16) & 255] ^ aesTe2[(s2 >> 8) & 255] ^ aesTe3[s3 & 255] ^ w[k];
      final int t1 = aesTe0[s1 >> 24] ^ aesTe1[(s2 >> 16) & 255] ^ aesTe2[(s3 >> 8) & 255] ^ aesTe3[s0 & 255] ^ w[k + 1];
      final int t2 = aesTe0[s2 >> 24] ^ aesTe1[(s3 >> 16) & 255] ^ aesTe2[(s0 >> 8) & 255] ^ aesTe3[s1 & 255] ^ w[k + 2];
      final int t3 = aesTe0[s3 >> 24] ^ aesTe1[(s0 >> 16) & 255] ^ aesTe2[(s1 >> 8) & 255] ^ aesTe3[s2 & 255] ^ w[k + 3];
      s0 = t0;
      s1 = t1;
      s2 = t2;
      s3 = t3;
    }
    final int k = 4 * rounds;
    final int o0 = ((aesSbox[s0 >> 24] << 24) | (aesSbox[(s1 >> 16) & 255] << 16) | (aesSbox[(s2 >> 8) & 255] << 8) | aesSbox[s3 & 255]) ^ w[k];
    final int o1 = ((aesSbox[s1 >> 24] << 24) | (aesSbox[(s2 >> 16) & 255] << 16) | (aesSbox[(s3 >> 8) & 255] << 8) | aesSbox[s0 & 255]) ^ w[k + 1];
    final int o2 = ((aesSbox[s2 >> 24] << 24) | (aesSbox[(s3 >> 16) & 255] << 16) | (aesSbox[(s0 >> 8) & 255] << 8) | aesSbox[s1 & 255]) ^ w[k + 2];
    final int o3 = ((aesSbox[s3 >> 24] << 24) | (aesSbox[(s0 >> 16) & 255] << 16) | (aesSbox[(s1 >> 8) & 255] << 8) | aesSbox[s2 & 255]) ^ w[k + 3];
    _put(dst, d, o0);
    _put(dst, d + 4, o1);
    _put(dst, d + 8, o2);
    _put(dst, d + 12, o3);
  }

  void decrypt(Uint8List src, int so, Uint8List dst, int d) {
    final Uint32List w = _k.dec;
    final int rounds = _k.rounds;
    final int top = 4 * rounds;
    var s0 = ((src[so] << 24) | (src[so + 1] << 16) | (src[so + 2] << 8) | src[so + 3]) ^ w[top];
    var s1 = ((src[so + 4] << 24) | (src[so + 5] << 16) | (src[so + 6] << 8) | src[so + 7]) ^ w[top + 1];
    var s2 = ((src[so + 8] << 24) | (src[so + 9] << 16) | (src[so + 10] << 8) | src[so + 11]) ^ w[top + 2];
    var s3 = ((src[so + 12] << 24) | (src[so + 13] << 16) | (src[so + 14] << 8) | src[so + 15]) ^ w[top + 3];
    for (var r = rounds - 1; r > 0; r--) {
      final int k = 4 * r;
      final int t0 = aesTd0[s0 >> 24] ^ aesTd1[(s3 >> 16) & 255] ^ aesTd2[(s2 >> 8) & 255] ^ aesTd3[s1 & 255] ^ w[k];
      final int t1 = aesTd0[s1 >> 24] ^ aesTd1[(s0 >> 16) & 255] ^ aesTd2[(s3 >> 8) & 255] ^ aesTd3[s2 & 255] ^ w[k + 1];
      final int t2 = aesTd0[s2 >> 24] ^ aesTd1[(s1 >> 16) & 255] ^ aesTd2[(s0 >> 8) & 255] ^ aesTd3[s3 & 255] ^ w[k + 2];
      final int t3 = aesTd0[s3 >> 24] ^ aesTd1[(s2 >> 16) & 255] ^ aesTd2[(s1 >> 8) & 255] ^ aesTd3[s0 & 255] ^ w[k + 3];
      s0 = t0;
      s1 = t1;
      s2 = t2;
      s3 = t3;
    }
    final int o0 = ((aesInvSbox[s0 >> 24] << 24) | (aesInvSbox[(s3 >> 16) & 255] << 16) | (aesInvSbox[(s2 >> 8) & 255] << 8) | aesInvSbox[s1 & 255]) ^ w[0];
    final int o1 = ((aesInvSbox[s1 >> 24] << 24) | (aesInvSbox[(s0 >> 16) & 255] << 16) | (aesInvSbox[(s3 >> 8) & 255] << 8) | aesInvSbox[s2 & 255]) ^ w[1];
    final int o2 = ((aesInvSbox[s2 >> 24] << 24) | (aesInvSbox[(s1 >> 16) & 255] << 16) | (aesInvSbox[(s0 >> 8) & 255] << 8) | aesInvSbox[s3 & 255]) ^ w[2];
    final int o3 = ((aesInvSbox[s3 >> 24] << 24) | (aesInvSbox[(s2 >> 16) & 255] << 16) | (aesInvSbox[(s1 >> 8) & 255] << 8) | aesInvSbox[s0 & 255]) ^ w[3];
    _put(dst, d, o0);
    _put(dst, d + 4, o1);
    _put(dst, d + 8, o2);
    _put(dst, d + 12, o3);
  }

  static void _put(Uint8List b, int o, int v) {
    b[o] = (v >> 24) & 0xFF;
    b[o + 1] = (v >> 16) & 0xFF;
    b[o + 2] = (v >> 8) & 0xFF;
    b[o + 3] = v & 0xFF;
  }
}

/// AES in counter mode. The same call encrypts and decrypts.
///
/// Keep one object per stream: [process] continues where the last call stopped.
class AesCtr {
  /// Creates a stream cipher.
  ///
  /// [key] is 16, 24 or 32 bytes. [counterBlock] is the 16-byte first counter
  /// value. The counter counts up as a big-endian number when
  /// [bigEndianCounter] is true (as NIST describes) and as a little-endian
  /// number when false (as WinZip AES does).
  AesCtr(Uint8List key, Uint8List counterBlock, {bool bigEndianCounter = true})
      : _aes = AesBlock(key),
        _big = bigEndianCounter,
        _counter = Uint8List.fromList(counterBlock) {
    if (counterBlock.length != 16) {
      throw ArgumentError('counter block must be 16 bytes');
    }
  }

  final AesBlock _aes;
  final bool _big;
  final Uint8List _counter;
  final Uint8List _stream = Uint8List(16);
  int _used = 16;

  void _increment() {
    if (_big) {
      for (var i = 15; i >= 0; i--) {
        _counter[i] = (_counter[i] + 1) & 0xFF;
        if (_counter[i] != 0) break;
      }
    } else {
      for (var i = 0; i < 16; i++) {
        _counter[i] = (_counter[i] + 1) & 0xFF;
        if (_counter[i] != 0) break;
      }
    }
  }

  /// Encrypts or decrypts [data] and returns the result.
  Uint8List process(Uint8List data) {
    final Uint8List out = Uint8List(data.length);
    for (var i = 0; i < data.length; i++) {
      if (_used == 16) {
        _aes.encrypt(_counter, 0, _stream, 0);
        _increment();
        _used = 0;
      }
      out[i] = data[i] ^ _stream[_used++];
    }
    return out;
  }
}

/// Encrypts [data] with AES-CBC without padding. [data] must be a multiple of
/// 16 bytes; [iv] is 16 bytes.
Uint8List aesCbcEncrypt(Uint8List key, Uint8List iv, Uint8List data) {
  if (data.length % 16 != 0) throw ArgumentError('length must be a multiple of 16');
  final AesBlock aes = AesBlock(key);
  final Uint8List out = Uint8List(data.length);
  final Uint8List block = Uint8List(16);
  Uint8List prev = Uint8List.fromList(iv);
  for (var o = 0; o < data.length; o += 16) {
    for (var i = 0; i < 16; i++) {
      block[i] = data[o + i] ^ prev[i];
    }
    aes.encrypt(block, 0, out, o);
    prev = Uint8List.sublistView(out, o, o + 16);
  }
  return out;
}

/// Decrypts [data] with AES-CBC without padding. [data] must be a multiple of
/// 16 bytes; [iv] is 16 bytes.
Uint8List aesCbcDecrypt(Uint8List key, Uint8List iv, Uint8List data) {
  if (data.length % 16 != 0) throw ArgumentError('length must be a multiple of 16');
  final AesBlock aes = AesBlock(key);
  final Uint8List out = Uint8List(data.length);
  final Uint8List ivCopy = Uint8List.fromList(iv);
  for (var o = 0; o < data.length; o += 16) {
    aes.decrypt(data, o, out, o);
    for (var i = 0; i < 16; i++) {
      out[o + i] ^= o == 0 ? ivCopy[i] : data[o - 16 + i];
    }
  }
  return out;
}
