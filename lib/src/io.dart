import 'dart:io';
import 'dart:typed_data';

import 'errors.dart';

typedef ChunkSink = void Function(Uint8List buf, int start, int end);

abstract class ByteInput {
  int get position;

  int readByte();

  int read(Uint8List buf, int off, int len);

  void skip(int n);

  int peek() => throw UnsupportedError('peek');

  Uint8List readExact(int n) {
    final Uint8List out = Uint8List(n);
    var got = 0;
    while (got < n) {
      final int r = read(out, got, n - got);
      if (r <= 0) throw const PzCorrupt('The file ends too early.');
      got += r;
    }
    return out;
  }

  int readU16le() {
    final int a = readByte();
    return a | (readByte() << 8);
  }

  int readU32le() {
    final int a = readByte();
    final int b = readByte();
    final int c = readByte();
    return a | (b << 8) | (c << 16) | (readByte() << 24);
  }

  int readU64le() {
    final int lo = readU32le();
    return lo | (readU32le() << 32);
  }
}

class BytesInput extends ByteInput {
  BytesInput(this._data, [int start = 0, int? end])
      : _pos = start,
        _start = start,
        _end = end ?? _data.length;

  final Uint8List _data;
  final int _start;
  final int _end;
  int _pos;

  @override
  int get position => _pos - _start;

  @override
  int peek() => _pos >= _end ? -1 : _data[_pos];

  @override
  int readByte() {
    if (_pos >= _end) throw const PzCorrupt('The file ends too early.');
    return _data[_pos++];
  }

  @override
  int read(Uint8List buf, int off, int len) {
    final int n = len < _end - _pos ? len : _end - _pos;
    if (n <= 0) return 0;
    buf.setRange(off, off + n, _data, _pos);
    _pos += n;
    return n;
  }

  @override
  void skip(int n) {
    if (n < 0 || n > _end - _pos) throw const PzCorrupt('The file ends too early.');
    _pos += n;
  }
}

class FileInput extends ByteInput {
  FileInput(this._file, int start, int end)
      : _next = start,
        _end = end,
        _start = start;

  final RandomAccessFile _file;
  final int _start;
  final int _end;

  int _next;
  final Uint8List _buf = Uint8List(65536);
  int _bufPos = 0;
  int _bufLen = 0;

  @override
  int get position => _next - _start - (_bufLen - _bufPos);

  bool _fill() {
    if (_next >= _end) return false;
    _file.setPositionSync(_next);
    int want = _buf.length;
    if (want > _end - _next) want = _end - _next;
    final int n = _file.readIntoSync(_buf, 0, want);
    if (n <= 0) return false;
    _next += n;
    _bufPos = 0;
    _bufLen = n;
    return true;
  }

  @override
  int peek() {
    if (_bufPos >= _bufLen && !_fill()) return -1;
    return _buf[_bufPos];
  }

  @override
  int readByte() {
    if (_bufPos >= _bufLen && !_fill()) {
      throw const PzCorrupt('The file ends too early.');
    }
    return _buf[_bufPos++];
  }

  @override
  int read(Uint8List buf, int off, int len) {
    if (len <= 0) return 0;
    if (_bufPos >= _bufLen && !_fill()) return 0;
    final int avail = _bufLen - _bufPos;
    final int n = len < avail ? len : avail;
    buf.setRange(off, off + n, _buf, _bufPos);
    _bufPos += n;
    return n;
  }

  @override
  void skip(int n) {
    if (n < 0 || n > _end - _start - position) {
      throw const PzCorrupt('The file ends too early.');
    }
    final int avail = _bufLen - _bufPos;
    if (n <= avail) {
      _bufPos += n;
    } else {
      _next += n - avail;
      _bufPos = 0;
      _bufLen = 0;
    }
  }
}

class LimitedInput extends ByteInput {
  LimitedInput(this._in, this.limit);

  final ByteInput _in;
  final int limit;
  int _used = 0;

  @override
  int get position => _used;

  @override
  int peek() => _used >= limit ? -1 : _in.peek();

  @override
  int readByte() {
    if (_used >= limit) throw const PzCorrupt('The file ends too early.');
    _used++;
    return _in.readByte();
  }

  @override
  int read(Uint8List buf, int off, int len) {
    final int left = limit - _used;
    if (left <= 0) return 0;
    final int n = _in.read(buf, off, len < left ? len : left);
    _used += n;
    return n;
  }

  @override
  void skip(int n) {
    if (n < 0 || n > limit - _used) throw const PzCorrupt('The file ends too early.');
    _in.skip(n);
    _used += n;
  }
}

class ByteBuilder {
  ByteBuilder([int capacity = 256]) : _buf = Uint8List(capacity < 16 ? 16 : capacity);

  Uint8List _buf;
  int _len = 0;

  int get length => _len;

  void _ensure(int extra) {
    final int need = _len + extra;
    if (need <= _buf.length) return;
    var cap = _buf.length * 2;
    while (cap < need) {
      cap *= 2;
    }
    final Uint8List n = Uint8List(cap);
    n.setRange(0, _len, _buf);
    _buf = n;
  }

  void addByte(int b) {
    _ensure(1);
    _buf[_len++] = b & 0xFF;
  }

  void addBytes(List<int> b, [int start = 0, int? end]) {
    final int e = end ?? b.length;
    _ensure(e - start);
    _buf.setRange(_len, _len + e - start, b, start);
    _len += e - start;
  }

  void addU16le(int v) {
    addByte(v);
    addByte(v >> 8);
  }

  void addU32le(int v) {
    addByte(v);
    addByte(v >> 8);
    addByte(v >> 16);
    addByte(v >> 24);
  }

  void addU64le(int v) {
    addU32le(v & 0xFFFFFFFF);
    addU32le((v >> 32) & 0xFFFFFFFF);
  }

  Uint8List view() => Uint8List.sublistView(_buf, 0, _len);

  Uint8List toBytes() => Uint8List.fromList(view());

  void clear() => _len = 0;
}

class BufferedOut {
  BufferedOut(this._file);

  final RandomAccessFile _file;
  final Uint8List _buf = Uint8List(65536);
  int _len = 0;
  int _flushed = 0;
  bool closed = false;

  int get position => _flushed + _len;

  void add(List<int> data, [int start = 0, int? end]) {
    final int e = end ?? data.length;
    var i = start;
    while (i < e) {
      final int room = _buf.length - _len;
      final int n = (e - i) < room ? (e - i) : room;
      _buf.setRange(_len, _len + n, data, i);
      _len += n;
      i += n;
      if (_len == _buf.length) _flush();
    }
  }

  void addByte(int b) {
    if (_len == _buf.length) _flush();
    _buf[_len++] = b & 0xFF;
  }

  void _flush() {
    if (_len == 0) return;
    _file.writeFromSync(_buf, 0, _len);
    _flushed += _len;
    _len = 0;
  }

  void patch(int pos, List<int> data) {
    _flush();
    _file.setPositionSync(pos);
    _file.writeFromSync(data);
    _file.setPositionSync(_flushed);
  }

  void close() {
    if (closed) return;
    closed = true;
    _flush();
    _file.closeSync();
  }
}

abstract class DataSink {
  void add(Uint8List buf, int start, int end);

  void close();

  void closeRaw();
}

class PlainSink extends DataSink {
  PlainSink(this.out);

  final BufferedOut out;

  @override
  void add(Uint8List buf, int start, int end) => out.add(buf, start, end);

  @override
  void close() => out.close();

  @override
  void closeRaw() {
    try {
      out.close();
    } catch (_) {}
  }
}
