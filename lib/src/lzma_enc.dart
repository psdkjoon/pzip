import 'dart:typed_data';

import 'errors.dart';
import 'io.dart';

const int _kStates = 12;
const int _oIsMatch = 0;
const int _oIsRep = _oIsMatch + _kStates * 16;
const int _oG0 = _oIsRep + _kStates;
const int _oG1 = _oG0 + _kStates;
const int _oG2 = _oG1 + _kStates;
const int _oRep0Long = _oG2 + _kStates;
const int _oPosSlot = _oRep0Long + _kStates * 16;
const int _oSpec = _oPosSlot + 4 * 64;
const int _oAlign = _oSpec + 115;
const int _oLen = _oAlign + 16;
const int _lenSize = 2 + 16 * 8 + 16 * 8 + 256;
const int _oRepLen = _oLen + _lenSize;
const int _oLit = _oRepLen + _lenSize;

const int _hashBits = 16;

class _RcEnc {
  int low = 0;
  int range = 0xFFFFFFFF;
  int cache = 0;
  int cacheSize = 1;
  final ByteBuilder out = ByteBuilder(65536);

  void _shiftLow() {
    if (low < 0xFF000000 || low >= 0x100000000) {
      final int carry = low >> 32;
      var temp = cache;
      do {
        out.addByte(temp + carry);
        temp = 0xFF;
        cacheSize--;
      } while (cacheSize != 0);
      cache = (low >> 24) & 0xFF;
    }
    cacheSize++;
    low = (low & 0x00FFFFFF) << 8;
  }

  void bit(Uint16List probs, int i, int b) {
    final int p = probs[i];
    final int bound = (range >> 11) * p;
    if (b == 0) {
      range = bound;
      probs[i] = p + ((2048 - p) >> 5);
    } else {
      low += bound;
      range -= bound;
      probs[i] = p - (p >> 5);
    }
    while (range < 0x1000000) {
      range = (range << 8) & 0xFFFFFFFF;
      _shiftLow();
    }
  }

  void direct(int v, int n) {
    for (var i = n - 1; i >= 0; i--) {
      range >>= 1;
      if (((v >> i) & 1) != 0) low += range;
      while (range < 0x1000000) {
        range = (range << 8) & 0xFFFFFFFF;
        _shiftLow();
      }
    }
  }

  void tree(Uint16List probs, int base, int bits, int v) {
    var m = 1;
    for (var i = bits - 1; i >= 0; i--) {
      final int b = (v >> i) & 1;
      bit(probs, base + m, b);
      m = (m << 1) | b;
    }
  }

  void rtree(Uint16List probs, int base, int bits, int v) {
    var m = 1;
    for (var i = 0; i < bits; i++) {
      final int b = (v >> i) & 1;
      bit(probs, base + m, b);
      m = (m << 1) | b;
    }
  }

  void flush() {
    for (var i = 0; i < 5; i++) {
      _shiftLow();
    }
  }

  int get sizeEstimate => out.length + cacheSize + 4;
}

int lzma2DictByte(int dict) {
  var b = 0;
  while (b < 40) {
    final int sz = (2 | (b & 1)) << (b ~/ 2 + 11);
    if (sz >= dict) return b;
    b++;
  }
  return 40;
}

class Lzma2Encoder {
  Lzma2Encoder(
    int level,
    this._out, {
    int? dictSize,
    int chunkCompressedLimit = 65536 - 100,
    this.cancel,
  })  : dict = dictSize ?? (level <= 3 ? (1 << 20) : (level <= 6 ? (1 << 22) : (1 << 23))),
        _depth = level <= 3 ? 8 : (level <= 6 ? 24 : 64),
        _lazy = level >= 4,
        _nice = level <= 3 ? 32 : (level <= 6 ? 64 : 273),
        _chunkC = chunkCompressedLimit {
    _block = dict > (1 << 16) ? dict : (1 << 16);
    _cap = dict + _block;
    _buf = Uint8List(_cap);
    var pc = 1;
    while (pc < dict) {
      pc <<= 1;
    }
    _prevMask = pc - 1;
    _prev = Int32List(pc);
    _chunkU = (1 << 20) - 273 < dict - 273 ? (1 << 20) - 273 : dict - 273;
    _reset();
  }

  final int dict;
  final int _depth;
  final bool _lazy;
  final int _nice;
  final int _chunkC;
  final CancelToken? cancel;
  final ChunkSink _out;

  late final int _block;
  late final int _cap;
  late final Uint8List _buf;
  late final int _prevMask;
  late final Int32List _prev;
  late final int _chunkU;
  final Int64List _head = Int64List(1 << _hashBits);

  int _base = 0;
  int _fill = 0;
  int _pos = 0;
  int _chunkStart = 0;

  bool _needDict = true;
  bool _needProps = true;
  bool _needState = false;

  static const int _lc = 3;
  static const int _lp = 0;
  static const int _pb = 2;

  late Uint16List _probs;
  int _state = 0;
  int _r0 = 0;
  int _r1 = 0;
  int _r2 = 0;
  int _r3 = 0;
  _RcEnc _rc = _RcEnc();

  int get dictProp => lzma2DictByte(dict);

  void _reset() {
    _probs = Uint16List(_oLit + (0x300 << (_lc + _lp)));
    _probs.fillRange(0, _probs.length, 1024);
    _state = 0;
    _r0 = _r1 = _r2 = _r3 = 0;
  }

  void add(Uint8List data, [int start = 0, int? end]) {
    final int e = end ?? data.length;
    var i = start;
    while (i < e) {
      if (cancel != null && cancel!.isCancelled) throw const PzCancelled();
      var room = _cap - (_fill - _base);
      if (room == 0) {
        _encode(false);
        _slide();
        room = _cap - (_fill - _base);
        if (room == 0) throw StateError('lzma2 buffer');
      }
      final int n = room < (e - i) ? room : (e - i);
      _buf.setRange(_fill - _base, _fill - _base + n, data, i);
      _fill += n;
      i += n;
    }
    if (_fill - _pos > _block ~/ 2) _encode(false);
  }

  void _slide() {
    var keep = _pos - dict;
    if (_chunkStart < keep) keep = _chunkStart;
    final int shift = keep - _base;
    if (shift > 0) {
      _buf.setRange(0, _fill - _base - shift, _buf, shift);
      _base += shift;
    }
  }

  void finish() {
    _encode(true);
    if (_pos > _chunkStart) _endChunk();
    final Uint8List z = Uint8List(1);
    _out(z, 0, 1);
  }

  int _hash(int i) {
    final int o = i - _base;
    return (((_buf[o] | (_buf[o + 1] << 8) | (_buf[o + 2] << 16)) * 2654435761) >> 12) &
        ((1 << _hashBits) - 1);
  }

  void _insert(int i, int avail) {
    if (avail < 3) return;
    final int h = _hash(i);
    final int old = _head[h] - 1;
    _prev[i & _prevMask] = (old >= 0 && i - old < dict) ? (i - old) : 0;
    _head[h] = i + 1;
  }

  int _mlen(int i, int j, int mx) {
    final int a = i - _base;
    final int c = j - _base;
    var n = 0;
    while (n < mx && _buf[a + n] == _buf[c + n]) {
      n++;
    }
    return n;
  }

  int _bestLen = 0;
  int _bestDist = 0;

  void _find(int i, int avail) {
    _bestLen = 0;
    _bestDist = 0;
    if (avail < 3) return;
    final int mx = avail < 273 ? avail : 273;
    var best = 0;
    var bd = 0;
    var cand = _head[_hash(i)] - 1;
    var depth = _depth;
    while (cand >= 0 && depth > 0) {
      final int d = i - cand;
      if (d >= dict || d <= 0) break;
      if (best == 0 || _buf[cand - _base + best] == _buf[i - _base + best]) {
        final int n = _mlen(i, cand, mx);
        if (n > best) {
          best = n;
          bd = d - 1;
          if (n >= _nice || n == mx) break;
        }
      }
      final int step = _prev[cand & _prevMask];
      if (step == 0) break;
      cand -= step;
      depth--;
    }
    _bestLen = best;
    _bestDist = bd;
  }

  void _lenEnc(int base, int ln, int ps) {
    final int l0 = ln - 2;
    if (l0 < 8) {
      _rc.bit(_probs, base, 0);
      _rc.tree(_probs, base + 2 + ps * 8, 3, l0);
    } else if (l0 < 16) {
      _rc.bit(_probs, base, 1);
      _rc.bit(_probs, base + 1, 0);
      _rc.tree(_probs, base + 2 + 128 + ps * 8, 3, l0 - 8);
    } else {
      _rc.bit(_probs, base, 1);
      _rc.bit(_probs, base + 1, 1);
      _rc.tree(_probs, base + 2 + 256, 8, l0 - 16);
    }
  }

  void _literal(int i, int ps) {
    final int st = _state;
    _rc.bit(_probs, _oIsMatch + (st << 4) + ps, 0);
    final int o = i - _base;
    final int prev = i > 0 ? _buf[o - 1] : 0;
    final int byte = _buf[o];
    final int base = _oLit + 0x300 * (((i & ((1 << _lp) - 1)) << _lc) + (prev >> (8 - _lc)));
    var sym = 1;
    if (st >= 7) {
      var mb = _buf[o - _r0 - 1];
      var offs = 0x100;
      for (var k = 7; k >= 0; k--) {
        final int b = (byte >> k) & 1;
        mb <<= 1;
        final int mbit = mb & offs;
        _rc.bit(_probs, base + offs + mbit + sym, b);
        sym = (sym << 1) | b;
        if (b == 0) {
          offs &= ~mbit;
        } else {
          offs &= mbit;
        }
      }
    } else {
      for (var k = 7; k >= 0; k--) {
        final int b = (byte >> k) & 1;
        _rc.bit(_probs, base + sym, b);
        sym = (sym << 1) | b;
      }
    }
    _state = st < 4 ? 0 : (st < 10 ? st - 3 : st - 6);
  }

  void _match(int ln, int d0, int ps) {
    final int st = _state;
    _rc.bit(_probs, _oIsMatch + (st << 4) + ps, 1);
    _rc.bit(_probs, _oIsRep + st, 0);
    _lenEnc(_oLen, ln, ps);
    final int l0 = ln - 2;
    final int ls = l0 < 4 ? l0 : 3;
    int slot;
    if (d0 < 4) {
      slot = d0;
    } else {
      final int n = d0.bitLength - 1;
      slot = 2 * n + ((d0 >> (n - 1)) & 1);
    }
    _rc.tree(_probs, _oPosSlot + ls * 64, 6, slot);
    if (slot >= 4) {
      final int nd = (slot >> 1) - 1;
      final int base = (2 | (slot & 1)) << nd;
      final int red = d0 - base;
      if (slot < 14) {
        var m = 1;
        final int sb = base - slot - 1;
        for (var i = 0; i < nd; i++) {
          final int b = (red >> i) & 1;
          _rc.bit(_probs, _oSpec + sb + m, b);
          m = (m << 1) | b;
        }
      } else {
        _rc.direct(red >> 4, nd - 4);
        _rc.rtree(_probs, _oAlign, 4, red & 15);
      }
    }
    _r3 = _r2;
    _r2 = _r1;
    _r1 = _r0;
    _r0 = d0;
    _state = st < 7 ? 7 : 10;
  }

  void _rep(int idx, int ln, int ps) {
    final int st = _state;
    _rc.bit(_probs, _oIsMatch + (st << 4) + ps, 1);
    _rc.bit(_probs, _oIsRep + st, 1);
    if (idx == 0) {
      _rc.bit(_probs, _oG0 + st, 0);
      _rc.bit(_probs, _oRep0Long + (st << 4) + ps, 1);
    } else {
      _rc.bit(_probs, _oG0 + st, 1);
      int d;
      if (idx == 1) {
        _rc.bit(_probs, _oG1 + st, 0);
        d = _r1;
      } else {
        _rc.bit(_probs, _oG1 + st, 1);
        _rc.bit(_probs, _oG2 + st, idx == 2 ? 0 : 1);
        if (idx == 2) {
          d = _r2;
        } else {
          d = _r3;
          _r3 = _r2;
        }
        _r2 = _r1;
      }
      _r1 = _r0;
      _r0 = d;
    }
    _lenEnc(_oRepLen, ln, ps);
    _state = st < 7 ? 8 : 11;
  }

  void _encode(bool last) {
    final int pbMask = (1 << _pb) - 1;
    while (true) {
      final int avail = _fill - _pos;
      if (avail == 0) return;
      if (!last && avail < 274) return;
      if (_pos == _chunkStart) _beginChunk();
      final int i = _pos;
      final int ps = i & pbMask;
      _find(i, avail);
      final int ln = _bestLen;
      final int d0 = _bestDist;
      var rl = 0;
      var ri = 0;
      final int mx = avail < 273 ? avail : 273;
      for (var r = 0; r < 4; r++) {
        final int d = r == 0 ? _r0 : (r == 1 ? _r1 : (r == 2 ? _r2 : _r3));
        if (d + 1 > i) continue;
        final int n = _mlen(i, i - d - 1, mx);
        if (n > rl) {
          rl = n;
          ri = r;
        }
      }
      var use = 0;
      if (rl >= 2 && rl + 1 >= ln) {
        use = 1;
      } else if (ln >= 3 && !(ln == 3 && d0 >= (1 << 14))) {
        use = 2;
      }
      if (use == 2 && _lazy && ln < _nice && avail > 4) {
        _find(i + 1, avail - 1);
        if (_bestLen > ln) use = 0;
      }
      int adv;
      if (use == 1) {
        _rep(ri, rl, ps);
        adv = rl;
      } else if (use == 2) {
        _match(ln, d0, ps);
        adv = ln;
      } else {
        _literal(i, ps);
        adv = 1;
      }
      for (var k = 0; k < adv; k++) {
        _insert(i + k, _fill - (i + k));
      }
      _pos += adv;
      if (_pos - _chunkStart >= _chunkU || _rc.sizeEstimate >= _chunkC) {
        _endChunk();
      }
    }
  }

  void _beginChunk() {
    if (_needDict || _needProps || _needState) _reset();
    _rc = _RcEnc();
  }

  void _endChunk() {
    final int usz = _pos - _chunkStart;
    _rc.flush();
    final Uint8List comp = _rc.out.view();
    if (comp.length > 65536) throw StateError('lzma2 chunk too big');
    if (comp.length >= usz) {
      var o = 0;
      while (o < usz) {
        final int n = usz - o < 65536 ? usz - o : 65536;
        final ByteBuilder b = ByteBuilder(n + 3);
        b.addByte(_needDict ? 1 : 2);
        _needDict = false;
        b.addByte((n - 1) >> 8);
        b.addByte((n - 1) & 0xFF);
        final int from = _chunkStart - _base + o;
        b.addBytes(_buf, from, from + n);
        _out(b.view(), 0, b.length);
        o += n;
      }
      _needState = true;
    } else {
      final int mode = _needDict ? 3 : (_needProps ? 2 : (_needState ? 1 : 0));
      final ByteBuilder b = ByteBuilder(comp.length + 8);
      b.addByte(0x80 | (mode << 5) | ((usz - 1) >> 16));
      b.addByte(((usz - 1) >> 8) & 0xFF);
      b.addByte((usz - 1) & 0xFF);
      b.addByte((comp.length - 1) >> 8);
      b.addByte((comp.length - 1) & 0xFF);
      if (mode >= 2) b.addByte(_lc + _lp * 9 + _pb * 45);
      b.addBytes(comp);
      _out(b.view(), 0, b.length);
      _needDict = false;
      _needProps = false;
      _needState = false;
    }
    _chunkStart = _pos;
  }
}
