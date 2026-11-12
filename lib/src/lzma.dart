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

class LzmaDecoder {
  LzmaDecoder(int dictSize, this._sink, {int? cap, this.cancel}) {
    var w = dictSize < 4096 ? 4096 : dictSize;
    if (cap != null) {
      final int c = cap < 1 ? 1 : cap;
      if (c < w) w = c;
    }
    if (w > (1 << 30)) {
      throw const PzUnsupported('The dictionary is too large for this device.');
    }
    _wsize = w;
    _win = Uint8List(w);
  }

  final ChunkSink _sink;
  final CancelToken? cancel;

  late final int _wsize;
  late final Uint8List _win;
  int _wpos = 0;
  int _full = 0;
  int _flushPos = 0;

  int total = 0;

  int _lc = 0;
  int _lp = 0;
  int _pb = 0;
  Uint16List _probs = Uint16List(0);
  int _state = 0;
  int _rep0 = 0;
  int _rep1 = 0;
  int _rep2 = 0;
  int _rep3 = 0;

  ByteInput? _in;
  int _range = 0;
  int _code = 0;

  void setProps(int d) {
    if (d >= 9 * 5 * 5) throw const PzCorrupt('Bad LZMA properties.');
    _lc = d % 9;
    d ~/= 9;
    _lp = d % 5;
    _pb = d ~/ 5;
    _probs = Uint16List(_oLit + (0x300 << (_lc + _lp)));
    resetState();
  }

  void resetState() {
    _probs.fillRange(0, _probs.length, 1024);
    _state = 0;
    _rep0 = _rep1 = _rep2 = _rep3 = 0;
  }

  void resetDict() {
    flush();
    _wpos = 0;
    _full = 0;
    _flushPos = 0;
    total = 0;
  }

  void startRc(ByteInput input) {
    _in = input;
    if (input.readByte() != 0) throw const PzCorrupt('Bad LZMA data.');
    var c = 0;
    for (var i = 0; i < 4; i++) {
      c = (c << 8) | input.readByte();
    }
    _code = c;
    _range = 0xFFFFFFFF;
    if (_code == _range) throw const PzCorrupt('Bad LZMA data.');
  }

  void finishRc() => _norm();

  void flush() {
    if (_wpos > _flushPos) {
      _sink(_win, _flushPos, _wpos);
    }
    _flushPos = _wpos;
    if (cancel != null && cancel!.isCancelled) throw const PzCancelled();
  }

  void _put(int b) {
    _win[_wpos++] = b;
    total++;
    if (_full < _wsize) _full++;
    if (_wpos == _wsize) {
      _sink(_win, _flushPos, _wsize);
      _wpos = 0;
      _flushPos = 0;
      if (cancel != null && cancel!.isCancelled) throw const PzCancelled();
    }
  }

  void copyUncompressed(ByteInput input, int n) {
    for (var i = 0; i < n; i++) {
      _put(input.readByte());
    }
  }

  void _norm() {
    if (_range < 0x1000000) {
      _range = (_range << 8) & 0xFFFFFFFF;
      _code = ((_code << 8) | _in!.readByte()) & 0xFFFFFFFF;
    }
  }

  int _bit(int i) {
    _norm();
    final int p = _probs[i];
    final int bound = (_range >> 11) * p;
    if (_code < bound) {
      _range = bound;
      _probs[i] = p + ((2048 - p) >> 5);
      return 0;
    }
    _range -= bound;
    _code -= bound;
    _probs[i] = p - (p >> 5);
    return 1;
  }

  int _direct(int n) {
    var r = 0;
    for (var i = 0; i < n; i++) {
      _norm();
      _range >>= 1;
      if (_code >= _range) {
        _code -= _range;
        r = (r << 1) | 1;
      } else {
        r <<= 1;
      }
    }
    return r;
  }

  int _tree(int base, int bits) {
    var m = 1;
    for (var i = 0; i < bits; i++) {
      m = (m << 1) | _bit(base + m);
    }
    return m - (1 << bits);
  }

  int _rtree(int base, int bits) {
    var m = 1;
    var r = 0;
    for (var i = 0; i < bits; i++) {
      final int b = _bit(base + m);
      m = (m << 1) | b;
      r |= b << i;
    }
    return r;
  }

  int _lenDec(int base, int ps) {
    if (_bit(base) == 0) return _tree(base + 2 + ps * 8, 3);
    if (_bit(base + 1) == 0) return 8 + _tree(base + 2 + 128 + ps * 8, 3);
    return 16 + _tree(base + 2 + 256, 8);
  }

  bool decode(int limit) {
    final int end = total + limit;
    final int pbMask = (1 << _pb) - 1;
    final int lpMask = (1 << _lp) - 1;
    while (total < end) {
      final int ps = total & pbMask;
      final int st = _state;
      if (_bit(_oIsMatch + (st << 4) + ps) == 0) {
        final int prev = _full == 0 ? 0 : _win[_wpos == 0 ? _wsize - 1 : _wpos - 1];
        final int base = _oLit + 0x300 * (((total & lpMask) << _lc) + (prev >> (8 - _lc)));
        var sym = 1;
        if (st >= 7) {
          var mb = _win[_back(_rep0)];
          var offs = 0x100;
          while (sym < 0x100) {
            mb <<= 1;
            final int bit = mb & offs;
            final int b = _bit(base + offs + bit + sym);
            sym = (sym << 1) | b;
            if (b == 0) {
              offs &= ~bit;
            } else {
              offs &= bit;
            }
          }
        } else {
          while (sym < 0x100) {
            sym = (sym << 1) | _bit(base + sym);
          }
        }
        _put(sym & 0xFF);
        _state = st < 4 ? 0 : (st < 10 ? st - 3 : st - 6);
        continue;
      }
      var ln = 0;
      if (_bit(_oIsRep + st) == 0) {
        _rep3 = _rep2;
        _rep2 = _rep1;
        _rep1 = _rep0;
        ln = _lenDec(_oLen, ps);
        _state = st < 7 ? 7 : 10;
        final int ls = ln < 4 ? ln : 3;
        final int slot = _tree(_oPosSlot + ls * 64, 6);
        int dist;
        if (slot < 4) {
          dist = slot;
        } else {
          final int nd = (slot >> 1) - 1;
          dist = (2 | (slot & 1)) << nd;
          if (slot < 14) {
            dist += _rtreeSpec(dist - slot - 1, nd);
          } else {
            dist += _direct(nd - 4) << 4;
            dist += _rtree(_oAlign, 4);
          }
        }
        if (dist == 0xFFFFFFFF) return true;
        _rep0 = dist;
      } else {
        if (_full == 0) throw const PzCorrupt('Bad LZMA data.');
        if (_bit(_oG0 + st) == 0) {
          if (_bit(_oRep0Long + (st << 4) + ps) == 0) {
            if (_rep0 >= _full) throw const PzCorrupt('Bad LZMA data.');
            _state = st < 7 ? 9 : 11;
            _put(_win[_back(_rep0)]);
            continue;
          }
        } else {
          int d;
          if (_bit(_oG1 + st) == 0) {
            d = _rep1;
          } else {
            if (_bit(_oG2 + st) == 0) {
              d = _rep2;
            } else {
              d = _rep3;
              _rep3 = _rep2;
            }
            _rep2 = _rep1;
          }
          _rep1 = _rep0;
          _rep0 = d;
        }
        ln = _lenDec(_oRepLen, ps);
        _state = st < 7 ? 8 : 11;
      }
      ln += 2;
      if (_rep0 >= _full) throw const PzCorrupt('Bad LZMA data.');
      if (ln > end - total) ln = end - total;
      for (var i = 0; i < ln; i++) {
        _put(_win[_back(_rep0)]);
      }
    }
    return false;
  }

  int _rtreeSpec(int base, int bits) {
    var m = 1;
    var r = 0;
    for (var i = 0; i < bits; i++) {
      final int b = _bit(_oSpec + base + m);
      m = (m << 1) | b;
      r |= b << i;
    }
    return r;
  }

  int _back(int d) {
    final int i = _wpos - d - 1;
    return i < 0 ? i + _wsize : i;
  }
}

int lzma2DictSize(int b) {
  if (b > 40) throw const PzCorrupt('Bad LZMA2 properties.');
  if (b == 40) return 0xFFFFFFFF;
  return (2 | (b & 1)) << (b ~/ 2 + 11);
}

int lzma2Decode(
  ByteInput input,
  int dictByte,
  ChunkSink sink, {
  int? cap,
  CancelToken? cancel,
}) {
  final LzmaDecoder z = LzmaDecoder(lzma2DictSize(dictByte), sink, cap: cap, cancel: cancel);
  var needDict = true;
  var needProps = true;
  var out = 0;
  while (true) {
    final int c = input.readByte();
    if (c == 0) break;
    if (c < 0x80) {
      if (c > 2) throw const PzCorrupt('Bad LZMA2 data.');
      if (c == 1) {
        z.resetDict();
        needDict = false;
      } else if (needDict) {
        throw const PzCorrupt('Bad LZMA2 data.');
      }
      final int n = ((input.readByte() << 8) | input.readByte()) + 1;
      z.copyUncompressed(input, n);
      out += n;
      continue;
    }
    final int usz = (((c & 0x1F) << 16) | (input.readByte() << 8) | input.readByte()) + 1;
    final int psz = ((input.readByte() << 8) | input.readByte()) + 1;
    final int mode = (c >> 5) & 3;
    if (mode == 3) {
      z.resetDict();
      needDict = false;
    }
    if (needDict) throw const PzCorrupt('Bad LZMA2 data.');
    if (mode >= 2) {
      z.setProps(input.readByte());
      needProps = false;
    } else if (needProps) {
      throw const PzCorrupt('Bad LZMA2 data.');
    } else if (mode == 1) {
      z.resetState();
    }
    final int start = input.position;
    z.startRc(input);
    z.decode(usz);
    z.finishRc();
    final int used = input.position - start;
    if (used > psz) throw const PzCorrupt('Bad LZMA2 data.');
    input.skip(psz - used);
    out += usz;
  }
  z.flush();
  return out;
}

int lzmaDecode(
  ByteInput input,
  Uint8List props,
  int unpackSize,
  ChunkSink sink, {
  CancelToken? cancel,
}) {
  if (props.length < 5) throw const PzCorrupt('Bad LZMA properties.');
  final int dict = props[1] | (props[2] << 8) | (props[3] << 16) | (props[4] << 24);
  final LzmaDecoder z = LzmaDecoder(dict, sink, cap: unpackSize, cancel: cancel);
  z.setProps(props[0]);
  z.startRc(input);
  z.decode(unpackSize);
  z.flush();
  return z.total;
}
