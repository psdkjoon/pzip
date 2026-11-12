import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'api.dart';
import 'errors.dart';
import 'gzip.dart';
import 'io.dart';
import 'reader_base.dart';
import 'writer_base.dart';
import 'xz.dart';

enum TarKind { file, dir, symlink, hardlink, other }

class TarItem {
  TarItem({
    required this.seq,
    required this.path,
    required this.size,
    required this.mode,
    required this.mtime,
    required this.kind,
    required this.linkName,
    required this.dataOffset,
  });

  final int seq;
  final String path;
  final int size;
  final int mode;
  final DateTime? mtime;
  final TarKind kind;
  final String? linkName;

  final int dataOffset;
}

class TarStream {
  TarStream(this._onStart, this._onEnd);

  final ChunkSink? Function(TarItem item) _onStart;
  final void Function(TarItem item) _onEnd;

  static const int _sHeader = 0;
  static const int _sData = 1;
  static const int _sPad = 2;
  static const int _sMeta = 3;

  int _state = _sHeader;
  final Uint8List _hdr = Uint8List(512);
  int _hdrLen = 0;
  int _remain = 0;
  int _pad = 0;
  int _pos = 0;
  int _zero = 0;
  int _seq = 0;
  TarItem? _cur;
  ChunkSink? _sink;
  ByteBuilder? _meta;
  int _metaType = 0;
  String? _longName;
  String? _longLink;
  final Map<String, String> _pax = <String, String>{};

  bool finished = false;

  int get skippable {
    if (finished) return 0;
    if (_state == _sData && _sink == null) return _remain + _pad;
    if (_state == _sPad) return _pad;
    return 0;
  }

  void skip(int n) {
    var left = n;
    while (left > 0) {
      if (_state == _sData) {
        final int m = left < _remain ? left : _remain;
        _remain -= m;
        left -= m;
        _pos += m;
        if (_remain == 0) _endData();
      } else if (_state == _sPad) {
        final int m = left < _pad ? left : _pad;
        _pad -= m;
        left -= m;
        _pos += m;
        if (_pad == 0) _state = _sHeader;
      } else {
        throw StateError('cannot skip here');
      }
    }
  }

  void feed(Uint8List b, int s, int e) {
    var i = s;
    while (i < e && !finished) {
      switch (_state) {
        case _sHeader:
          final int take = (512 - _hdrLen) < (e - i) ? (512 - _hdrLen) : (e - i);
          _hdr.setRange(_hdrLen, _hdrLen + take, b, i);
          _hdrLen += take;
          i += take;
          _pos += take;
          if (_hdrLen == 512) {
            _hdrLen = 0;
            _header();
          }
          break;
        case _sData:
          final int nd = _remain < (e - i) ? _remain : (e - i);
          final ChunkSink? sk = _sink;
          if (sk != null && nd > 0) sk(b, i, i + nd);
          i += nd;
          _pos += nd;
          _remain -= nd;
          if (_remain == 0) _endData();
          break;
        case _sPad:
          final int np = _pad < (e - i) ? _pad : (e - i);
          i += np;
          _pos += np;
          _pad -= np;
          if (_pad == 0) _state = _sHeader;
          break;
        case _sMeta:
          final int nm = _remain < (e - i) ? _remain : (e - i);
          _meta!.addBytes(b, i, i + nm);
          i += nm;
          _pos += nm;
          _remain -= nm;
          if (_remain == 0) _endMeta();
          break;
      }
    }
  }

  void _endData() {
    final TarItem it = _cur!;
    _cur = null;
    _sink = null;
    _state = _pad > 0 ? _sPad : _sHeader;
    _onEnd(it);
  }

  int _num(int off, int len) {
    if ((_hdr[off] & 0x80) != 0) {
      var v = _hdr[off] & 0x7F;
      for (var i = 1; i < len; i++) {
        v = (v << 8) | _hdr[off + i];
      }
      return v;
    }
    var v = 0;
    var i = off;
    final int end = off + len;
    while (i < end && _hdr[i] == 0x20) {
      i++;
    }
    while (i < end && _hdr[i] >= 0x30 && _hdr[i] <= 0x37) {
      v = (v << 3) | (_hdr[i] - 0x30);
      i++;
    }
    return v;
  }

  String _str(int off, int len) {
    var end = off;
    while (end < off + len && _hdr[end] != 0) {
      end++;
    }
    return utf8.decode(Uint8List.sublistView(_hdr, off, end), allowMalformed: true);
  }

  void _header() {
    var allZero = true;
    for (var i = 0; i < 512; i++) {
      if (_hdr[i] != 0) {
        allZero = false;
        break;
      }
    }
    if (allZero) {
      _zero++;
      if (_zero >= 2) finished = true;
      return;
    }
    _zero = 0;
    var sum = 0;
    for (var i = 0; i < 512; i++) {
      sum += (i >= 148 && i < 156) ? 0x20 : _hdr[i];
    }
    if (sum != _num(148, 8)) throw const PzCorrupt('This is not a tar file.');
    final int type = _hdr[156];
    var size = _num(124, 12);
    final int mode = _num(100, 8);
    var mtime = _num(136, 12);
    var name = _str(0, 100);
    final bool posix = _hdr[257] == 0x75 &&
        _hdr[258] == 0x73 &&
        _hdr[259] == 0x74 &&
        _hdr[260] == 0x61 &&
        _hdr[261] == 0x72 &&
        _hdr[262] == 0 &&
        _hdr[263] == 0x30 &&
        _hdr[264] == 0x30;
    if (posix) {
      final String prefix = _str(345, 155);
      if (prefix.isNotEmpty) name = '$prefix/$name';
    }
    String? link = _hdr[157] == 0 ? null : _str(157, 100);

    if (type == 0x4C || type == 0x4B || type == 0x78 || type == 0x67) {
      _metaType = type;
      _meta = ByteBuilder(size < 64 ? 64 : (size > 1 << 20 ? 1 << 20 : size));
      if (size > (1 << 20)) throw const PzCorrupt('Bad tar header.');
      _remain = size;
      _pad = (512 - size % 512) % 512;
      _state = _sMeta;
      if (size == 0) _endMeta();
      return;
    }

    if (_longName != null) name = _longName!;
    if (_longLink != null) link = _longLink;
    final String? pp = _pax['path'];
    if (pp != null) name = pp;
    final String? pl = _pax['linkpath'];
    if (pl != null) link = pl;
    final String? ps = _pax['size'];
    if (ps != null) size = int.tryParse(ps) ?? size;
    final String? pm = _pax['mtime'];
    if (pm != null) {
      final double? d = double.tryParse(pm);
      if (d != null) mtime = d.floor();
    }
    _longName = null;
    _longLink = null;
    _pax.clear();

    TarKind kind;
    switch (type) {
      case 0x30:
      case 0:
      case 0x37:
        kind = name.endsWith('/') ? TarKind.dir : TarKind.file;
        break;
      case 0x35:
        kind = TarKind.dir;
        break;
      case 0x32:
        kind = TarKind.symlink;
        break;
      case 0x31:
        kind = TarKind.hardlink;
        break;
      default:
        kind = TarKind.other;
    }
    if (kind == TarKind.dir || kind == TarKind.symlink || kind == TarKind.hardlink) {
      size = 0;
    }
    final TarItem item = TarItem(
      seq: kind == TarKind.other ? -1 : _seq++,
      path: name,
      size: size,
      mode: mode,
      mtime: mtime == 0 ? null : DateTime.fromMillisecondsSinceEpoch(mtime * 1000),
      kind: kind,
      linkName: link,
      dataOffset: _pos,
    );
    _cur = item;
    _sink = _onStart(item);
    _remain = size;
    _pad = (512 - size % 512) % 512;
    if (size == 0) {
      _endData();
    } else {
      _state = _sData;
    }
  }

  void _endMeta() {
    final Uint8List data = _meta!.view();
    final int type = _metaType;
    if (type == 0x4C || type == 0x4B) {
      var end = 0;
      while (end < data.length && data[end] != 0) {
        end++;
      }
      final String v = utf8.decode(Uint8List.sublistView(data, 0, end), allowMalformed: true);
      if (type == 0x4C) {
        _longName = v;
      } else {
        _longLink = v;
      }
    } else if (type == 0x78) {
      var p = 0;
      while (p < data.length) {
        var sp = p;
        while (sp < data.length && data[sp] != 0x20) {
          sp++;
        }
        final int? len = int.tryParse(ascii.decode(Uint8List.sublistView(data, p, sp), allowInvalid: true));
        if (len == null || len <= 0 || p + len > data.length) break;
        final String rec = utf8.decode(Uint8List.sublistView(data, sp + 1, p + len - 1), allowMalformed: true);
        final int eq = rec.indexOf('=');
        if (eq > 0) _pax[rec.substring(0, eq)] = rec.substring(eq + 1);
        p += len;
      }
    }
    _meta = null;
    _state = _pad > 0 ? _sPad : _sHeader;
  }
}

class TarReader extends ReaderBase {
  TarReader._(super.path, this._format, this._raf, this._len);

  final ArchiveFormat _format;
  final RandomAccessFile _raf;
  final int _len;
  final List<PzEntry> _entries = <PzEntry>[];
  final List<TarItem> _items = <TarItem>[];

  static TarReader open(String path, ArchiveFormat format) {
    final RandomAccessFile raf = File(path).openSync();
    final TarReader r = TarReader._(path, format, raf, raf.lengthSync());
    try {
      r._load();
    } catch (_) {
      raf.closeSync();
      rethrow;
    }
    return r;
  }

  bool get _plain => _format == ArchiveFormat.tar;

  void _pump(TarStream ts, CancelToken? cancel) {
    try {
      switch (_format) {
        case ArchiveFormat.tarGz:
          gzDecode(_raf, _len, (Uint8List b, int s, int e) {
            ts.feed(b, s, e);
            if (ts.finished) throw const PzStop();
          }, cancel: cancel);
          break;
        case ArchiveFormat.tarXz:
          xzDecode(FileInput(_raf, 0, _len), (Uint8List b, int s, int e) {
            ts.feed(b, s, e);
            if (ts.finished) throw const PzStop();
          }, cancel: cancel);
          break;
        default:
          final FileInput input = FileInput(_raf, 0, _len);
          final Uint8List buf = Uint8List(65536);
          while (!ts.finished) {
            if (cancel != null && cancel.isCancelled) throw const PzCancelled();
            final int left = _len - input.position;
            if (left <= 0) break;
            final int sk = ts.skippable;
            if (sk > 0) {
              final int n = sk < left ? sk : left;
              input.skip(n);
              ts.skip(n);
            } else {
              final int n = input.read(buf, 0, buf.length);
              if (n <= 0) break;
              ts.feed(buf, 0, n);
            }
          }
      }
    } on PzStop {
    }
  }

  void _load() {
    final TarStream ts = TarStream((TarItem it) {
      if (it.kind == TarKind.other) return null;
      var rel = it.path.replaceAll('\\', '/');
      while (rel.startsWith('/')) {
        rel = rel.substring(1);
      }
      while (rel.endsWith('/')) {
        rel = rel.substring(0, rel.length - 1);
      }
      while (rel.startsWith('./')) {
        rel = rel.substring(2);
      }
      if (rel.isEmpty || rel == '.') {
        _items.add(it);
        _entries.add(PzEntry(path: '.', isDir: true, size: 0, packedSize: 0));
        return null;
      }
      _items.add(it);
      _entries.add(PzEntry(
        path: rel,
        isDir: it.kind == TarKind.dir,
        size: it.kind == TarKind.file ? it.size : 0,
        packedSize: _plain ? (it.kind == TarKind.file ? it.size : 0) : -1,
        modified: it.mtime,
        mode: it.mode & 0xFFF,
        linkTarget: (it.kind == TarKind.symlink || it.kind == TarKind.hardlink) ? it.linkName : null,
      ));
      return null;
    }, (TarItem it) {});
    _pump(ts, null);
    final List<PzEntry> keepE = <PzEntry>[];
    final List<TarItem> keepI = <TarItem>[];
    for (var i = 0; i < _entries.length; i++) {
      if (_entries[i].path == '.' && _entries[i].isDir) continue;
      keepE.add(_entries[i]);
      keepI.add(_items[i]);
    }
    _entries
      ..clear()
      ..addAll(keepE);
    _items
      ..clear()
      ..addAll(keepI);
  }

  @override
  ArchiveFormat get format => _format;

  @override
  List<PzEntry> get entries => _entries;

  @override
  bool get hasEncryptedEntries => false;

  @override
  bool get isSolid => !_plain;

  @override
  Future<void> close() async {
    try {
      _raf.closeSync();
    } catch (_) {}
  }

  int _indexOf(PzEntry e) {
    for (var i = 0; i < _entries.length; i++) {
      if (identical(_entries[i], e)) return i;
    }
    throw const PzException('Not an entry of this archive.');
  }

  @override
  void decodeEntry(PzEntry entry, ChunkSink sink, CancelToken? cancel) {
    decodeMany(<PzEntry>[entry], (PzEntry e) => sink, (PzEntry e) {}, cancel);
  }

  @override
  void decodeMany(
    List<PzEntry> wanted,
    EntryOpener open,
    EntryCloser close,
    CancelToken? cancel,
  ) {
    if (wanted.isEmpty) return;
    if (_plain) {
      final Uint8List buf = Uint8List(65536);
      for (final PzEntry e in wanted) {
        if (cancel != null && cancel.isCancelled) throw const PzCancelled();
        final TarItem it = _items[_indexOf(e)];
        final ChunkSink? s = open(e);
        if (s == null) continue;
        var left = it.size;
        var pos = it.dataOffset;
        while (left > 0) {
          if (cancel != null && cancel.isCancelled) throw const PzCancelled();
          _raf.setPositionSync(pos);
          final int n = _raf.readIntoSync(buf, 0, left < buf.length ? left : buf.length);
          if (n <= 0) throw const PzCorrupt('The file ends too early.');
          s(buf, 0, n);
          left -= n;
          pos += n;
        }
        close(e);
      }
      return;
    }
    final Map<int, PzEntry> byIndex = <int, PzEntry>{};
    for (final PzEntry e in wanted) {
      byIndex[_indexOf(e)] = e;
    }
    var remaining = byIndex.length;
    final Set<int> opened = <int>{};
    final TarStream ts = TarStream((TarItem it) {
      if (it.kind == TarKind.other) return null;
      final PzEntry? e = byIndex[_itemIndex(it)];
      if (e == null) return null;
      final ChunkSink? s = open(e);
      if (s != null) opened.add(it.seq);
      return s;
    }, (TarItem it) {
      if (it.kind == TarKind.other) return;
      final PzEntry? e = byIndex[_itemIndex(it)];
      if (e == null) return;
      if (opened.remove(it.seq)) close(e);
      remaining--;
      if (remaining <= 0) throw const PzStop();
    });
    _pump(ts, cancel);
  }

  int _itemIndex(TarItem it) {
    var lo = 0;
    var hi = _items.length - 1;
    while (lo <= hi) {
      final int mid = (lo + hi) >> 1;
      final int off = _items[mid].dataOffset;
      if (off == it.dataOffset) return mid;
      if (off < it.dataOffset) {
        lo = mid + 1;
      } else {
        hi = mid - 1;
      }
    }
    return -1;
  }
}

class TarWriter extends WriterBase {
  TarWriter(super.outPath, super.options, super.onProgress, super.cancel, this._sink);

  final DataSink _sink;

  void _put(Uint8List b, int s, int e) => _sink.add(b, s, e);

  static void _octal(Uint8List h, int off, int len, int value) {
    final String s = value.toRadixString(8).padLeft(len - 1, '0');
    for (var i = 0; i < len - 1; i++) {
      h[off + i] = s.codeUnitAt(i);
    }
    h[off + len - 1] = 0;
  }

  static void _text(Uint8List h, int off, Uint8List bytes) {
    h.setRange(off, off + bytes.length, bytes);
  }

  Uint8List _header(
    Uint8List nameBytes,
    int mode,
    int size,
    int mtime,
    int type,
    Uint8List? linkBytes,
    Uint8List prefixBytes,
  ) {
    final Uint8List h = Uint8List(512);
    _text(h, 0, nameBytes);
    _octal(h, 100, 8, mode & 0xFFF);
    _octal(h, 108, 8, 0);
    _octal(h, 116, 8, 0);
    if (size >= 0x1FFFFFFFF) {
      h[124] = 0x80;
      var v = size;
      for (var i = 135; i >= 125; i--) {
        h[i] = v & 0xFF;
        v >>= 8;
      }
    } else {
      _octal(h, 124, 12, size);
    }
    _octal(h, 136, 12, mtime < 0 ? 0 : mtime);
    h[156] = type;
    if (linkBytes != null) _text(h, 157, linkBytes);
    _text(h, 257, Uint8List.fromList(<int>[0x75, 0x73, 0x74, 0x61, 0x72, 0, 0x30, 0x30]));
    if (prefixBytes.isNotEmpty) _text(h, 345, prefixBytes);
    for (var i = 148; i < 156; i++) {
      h[i] = 0x20;
    }
    var sum = 0;
    for (var i = 0; i < 512; i++) {
      sum += h[i];
    }
    final String cs = sum.toRadixString(8).padLeft(6, '0');
    for (var i = 0; i < 6; i++) {
      h[148 + i] = cs.codeUnitAt(i);
    }
    h[154] = 0;
    h[155] = 0x20;
    return h;
  }

  Uint8List _paxBlock(Map<String, String> rec) {
    final ByteBuilder b = ByteBuilder(256);
    rec.forEach((String k, String v) {
      final Uint8List body = Uint8List.fromList(utf8.encode(' $k=$v\n'));
      var len = body.length + 1;
      while (len.toString().length + body.length != len) {
        len = len.toString().length + body.length;
      }
      b.addBytes(utf8.encode('$len'));
      b.addBytes(body);
    });
    return b.toBytes();
  }

  void _writeBlockData(Uint8List data) {
    _put(data, 0, data.length);
    final int pad = (512 - data.length % 512) % 512;
    if (pad > 0) _put(Uint8List(pad), 0, pad);
  }

  @override
  void addEntry(EntryMeta m, void Function(PutChunk put)? produce) {
    checkCancel();
    final bool isDir = m.isDir;
    final String path = m.path;
    final int mode = m.mode ?? (isDir ? 0x1ED : 0x1A4);
    final int mtime = (m.modified ?? DateTime.now()).millisecondsSinceEpoch ~/ 1000;
    final Uint8List fullName = Uint8List.fromList(utf8.encode(isDir ? '$path/' : path));
    var nameBytes = fullName;
    var prefixBytes = Uint8List(0);
    final Map<String, String> pax = <String, String>{};
    if (fullName.length > 100) {
      var split = -1;
      for (var i = fullName.length - 2; i > 0; i--) {
        if (fullName[i] == 0x2F && i <= 155 && fullName.length - i - 1 <= 100) {
          split = i;
          break;
        }
      }
      if (split > 0) {
        prefixBytes = Uint8List.sublistView(fullName, 0, split);
        nameBytes = Uint8List.sublistView(fullName, split + 1);
      } else {
        pax['path'] = isDir ? '$path/' : path;
        nameBytes = Uint8List.sublistView(fullName, 0, 100);
      }
    }
    Uint8List? linkBytes;
    if (m.isLink) {
      final Uint8List lb = Uint8List.fromList(utf8.encode(m.linkTarget!));
      if (lb.length > 100) {
        pax['linkpath'] = m.linkTarget!;
        linkBytes = Uint8List.sublistView(lb, 0, 100);
      } else {
        linkBytes = lb;
      }
    }
    final int size = (isDir || m.isLink) ? 0 : m.size;
    if (pax.isNotEmpty) {
      final Uint8List data = _paxBlock(pax);
      final Uint8List pn = Uint8List.fromList(utf8.encode('PaxHeader/${path.split('/').last}'));
      final Uint8List ph = _header(
        pn.length > 100 ? Uint8List.sublistView(pn, 0, 100) : pn,
        0x1A4,
        data.length,
        mtime,
        0x78,
        null,
        Uint8List(0),
      );
      _put(ph, 0, 512);
      _writeBlockData(data);
    }
    final int type = isDir ? 0x35 : (m.isLink ? 0x32 : 0x30);
    final Uint8List h = _header(nameBytes, mode, size, mtime, type, linkBytes, prefixBytes);
    _put(h, 0, 512);
    if (size > 0 && produce != null) {
      var written = 0;
      produce((Uint8List b, int s, int e) {
        var n = e - s;
        if (written + n > size) n = size - written;
        if (n > 0) {
          _put(b, s, s + n);
          written += n;
        }
      });
      if (written < size) {
        final Uint8List zeros = Uint8List(size - written < 65536 ? size - written : 65536);
        var left = size - written;
        while (left > 0) {
          final int n = left < zeros.length ? left : zeros.length;
          _put(zeros, 0, n);
          left -= n;
        }
      }
      final int pad = (512 - size % 512) % 512;
      if (pad > 0) _put(Uint8List(pad), 0, pad);
    } else if (produce != null) {
      produce((Uint8List b, int s, int e) {});
    }
  }

  @override
  void finishFormat() {
    final Uint8List z = Uint8List(1024);
    _sink.add(z, 0, 1024);
    _sink.close();
  }

  @override
  void closeRaw() => _sink.closeRaw();
}
