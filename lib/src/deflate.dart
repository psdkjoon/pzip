import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'errors.dart';
import 'io.dart';

class _Collector implements Sink<List<int>> {
  _Collector(this._onData);

  final void Function(Uint8List) _onData;

  @override
  void add(List<int> data) {
    if (data.isEmpty) return;
    _onData(data is Uint8List ? data : Uint8List.fromList(data));
  }

  @override
  void close() {}
}

class RawInflater {
  RawInflater(void Function(Uint8List) onData)
      : _sink = ZLibDecoder(raw: true).startChunkedConversion(_Collector(onData));

  final ByteConversionSink _sink;
  bool _closed = false;

  void add(Uint8List data, [int start = 0, int? end]) {
    try {
      _sink.addSlice(data, start, end ?? data.length, false);
    } on PzException {
      rethrow;
    } catch (_) {
      throw const PzCorrupt('The compressed data is damaged.');
    }
  }

  void close() {
    if (_closed) return;
    _closed = true;
    try {
      _sink.close();
    } on PzException {
      rethrow;
    } catch (_) {
      throw const PzCorrupt('The compressed data is damaged.');
    }
  }
}

class RawDeflater {
  RawDeflater(int level, void Function(Uint8List) onData)
      : _sink = ZLibEncoder(raw: true, level: level < 1 ? 1 : (level > 9 ? 9 : level))
            .startChunkedConversion(_Collector(onData));

  final ByteConversionSink _sink;
  bool _closed = false;

  void add(Uint8List data, [int start = 0, int? end]) {
    _sink.addSlice(data, start, end ?? data.length, false);
  }

  void close() {
    if (_closed) return;
    _closed = true;
    _sink.close();
  }
}

int inflateRaw(
  ByteInput input,
  int packedSize,
  ChunkSink sink, {
  CancelToken? cancel,
}) {
  var produced = 0;
  final RawInflater inf = RawInflater((Uint8List out) {
    produced += out.length;
    sink(out, 0, out.length);
  });
  final Uint8List buf = Uint8List(65536);
  var left = packedSize;
  while (left > 0) {
    if (cancel != null && cancel.isCancelled) throw const PzCancelled();
    final int n = input.read(buf, 0, left < buf.length ? left : buf.length);
    if (n <= 0) throw const PzCorrupt('The file ends too early.');
    left -= n;
    inf.add(buf, 0, n);
  }
  inf.close();
  return produced;
}
