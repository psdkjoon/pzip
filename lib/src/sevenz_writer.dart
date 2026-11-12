import 'dart:io';
import 'dart:typed_data';

import 'aes.dart';
import 'api.dart';
import 'errors.dart';
import 'hash.dart';
import 'io.dart';
import 'lzma_enc.dart';
import 'sevenz_common.dart';
import 'writer_base.dart';

class _AesCbcOut {
  _AesCbcOut(this._out, Uint8List key, Uint8List iv)
      : _aes = AesBlock(key),
        _prev = Uint8List.fromList(iv);

  final BufferedOut _out;
  final AesBlock _aes;
  final Uint8List _prev;
  final Uint8List _pend = Uint8List(16);
  final Uint8List _x = Uint8List(16);
  final Uint8List _ct = Uint8List(16);
  int _pendLen = 0;

  int written = 0;

  void _block(Uint8List src, int o) {
    for (var i = 0; i < 16; i++) {
      _x[i] = src[o + i] ^ _prev[i];
    }
    _aes.encrypt(_x, 0, _ct, 0);
    _out.add(_ct);
    _prev.setRange(0, 16, _ct);
    written += 16;
  }

  void add(Uint8List b, int s, int e) {
    var i = s;
    if (_pendLen > 0) {
      while (i < e && _pendLen < 16) {
        _pend[_pendLen++] = b[i++];
      }
      if (_pendLen == 16) {
        _block(_pend, 0);
        _pendLen = 0;
      }
    }
    while (e - i >= 16) {
      _block(b, i);
      i += 16;
    }
    while (i < e) {
      _pend[_pendLen++] = b[i++];
    }
  }

  void finish() {
    if (_pendLen > 0) {
      for (var i = _pendLen; i < 16; i++) {
        _pend[i] = 0;
      }
      _block(_pend, 0);
      _pendLen = 0;
    }
  }
}

class _Sub {
  _Sub(this.size, this.crc);

  final int size;
  final int crc;
}

class _FolderOut {
  _FolderOut({
    required this.out,
    required this.level,
    required this.aesProps,
    required this.aesKey,
    required this.cancel,
    this.smallDict = false,
  }) {
    final Uint8List? key = aesKey;
    if (key != null) {
      final Uint8List iv = randomBytes(16);
      final Uint8List p = aesProps!;
      final Uint8List full = Uint8List.fromList(p);
      full.setRange(full.length - 16, full.length, iv);
      props = full;
      _aes = _AesCbcOut(out, key, iv);
    }
    if (level > 0) {
      _lz = Lzma2Encoder(level, _emit, dictSize: smallDict ? (1 << 20) : null, cancel: cancel);
    }
    startPos = out.position;
  }

  final BufferedOut out;
  final int level;
  final Uint8List? aesProps;
  final Uint8List? aesKey;
  final CancelToken? cancel;
  final bool smallDict;

  Uint8List? props;
  _AesCbcOut? _aes;
  Lzma2Encoder? _lz;
  late final int startPos;
  final List<_Sub> subs = <_Sub>[];
  int unpackSize = 0;
  int coderSize = 0;
  int packSize = 0;

  bool get encrypted => _aes != null;

  int get lzDictProp => _lz!.dictProp;

  void _emit(Uint8List b, int s, int e) {
    coderSize += e - s;
    final _AesCbcOut? a = _aes;
    if (a != null) {
      a.add(b, s, e);
    } else {
      out.add(b, s, e);
    }
  }

  void add(Uint8List b, int s, int e) {
    unpackSize += e - s;
    final Lzma2Encoder? lz = _lz;
    if (lz != null) {
      lz.add(b, s, e);
    } else {
      _emit(b, s, e);
    }
  }

  void close() {
    _lz?.finish();
    _aes?.finish();
    packSize = out.position - startPos;
  }
}

class _Item {
  _Item(this.path, this.attrs, this.mtime);

  final String path;
  final int attrs;
  final int mtime;
  bool emptyStream = true;
  bool emptyFile = false;
}

class SevenZWriter extends WriterBase {
  SevenZWriter._(
    super.outPath,
    super.options,
    super.onProgress,
    super.cancel,
    this._out,
  ) {
    _out.add(Uint8List(32));
    final String? pw = options.password;
    if (pw != null) {
      _salt = randomBytes(16);
      _key = sevenZipKey(_salt!, 19, pw);
    }
  }

  final BufferedOut _out;
  final List<_Item> _items = <_Item>[];
  final List<_FolderOut> _folders = <_FolderOut>[];
  _FolderOut? _open;
  Uint8List? _salt;
  Uint8List? _key;

  static SevenZWriter create(
    String outPath,
    WriteOptions options,
    void Function(int)? onProgress,
    CancelToken? cancel,
  ) {
    final RandomAccessFile f = File(outPath).openSync(mode: FileMode.write);
    return SevenZWriter._(outPath, options, onProgress, cancel, BufferedOut(f));
  }

  Uint8List? get _aesProps {
    if (_salt == null) return null;
    final ByteBuilder b = ByteBuilder(40);
    b.addByte(19 | 0x80 | 0x40);
    b.addByte((15 << 4) | 15);
    b.addBytes(_salt!);
    b.addBytes(Uint8List(16));
    return b.toBytes();
  }

  _FolderOut _newFolder() => _FolderOut(
        out: _out,
        level: options.level,
        aesProps: _aesProps,
        aesKey: _key,
        cancel: cancel,
        smallDict: !options.solid,
      );

  void _closeFolder() {
    final _FolderOut? f = _open;
    if (f == null) return;
    f.close();
    _folders.add(f);
    _open = null;
  }

  static int _fileTime(DateTime d) =>
      d.toUtc().microsecondsSinceEpoch * 10 + 116444736000000000;

  @override
  void addEntry(EntryMeta m, void Function(PutChunk put)? produce) {
    checkCancel();
    final int mode = m.mode ?? (m.isDir ? 0x1ED : (m.isLink ? 0x1FF : 0x1A4));
    final int typeBits = m.isDir ? 0x4000 : (m.isLink ? 0xA000 : 0x8000);
    final int attrs = (m.isDir ? 0x10 : 0x20) | 0x8000 | (((typeBits | mode) & 0xFFFF) << 16);
    final _Item item = _Item(m.path, attrs, _fileTime(m.modified ?? DateTime.now()));
    _items.add(item);
    if (m.isDir || produce == null) {
      item.emptyStream = true;
      item.emptyFile = false;
      return;
    }
    final Crc32 crc = Crc32();
    var size = 0;
    _FolderOut? folder;
    produce((Uint8List b, int s, int e) {
      if (e <= s) return;
      if (folder == null) {
        if (!options.solid) _closeFolder();
        folder = _open ??= _newFolder();
      }
      crc.add(Uint8List.sublistView(b, s, e));
      size += e - s;
      folder!.add(b, s, e);
    });
    if (size == 0) {
      item.emptyStream = true;
      item.emptyFile = true;
      return;
    }
    item.emptyStream = false;
    folder!.subs.add(_Sub(size, crc.value));
    if (!options.solid) _closeFolder();
  }

  void _writeFolder(ByteBuilder b, _FolderOut f) {
    final bool aes = f.encrypted;
    final bool copy = f.level <= 0;
    b.addByte(aes ? 2 : 1);
    if (aes) {
      b.addByte(4 | 0x20);
      b.addBytes(<int>[0x06, 0xF1, 0x07, 0x01]);
      szWriteNum(b, f.props!.length);
      b.addBytes(f.props!);
    }
    if (copy) {
      b.addByte(1);
      b.addByte(0x00);
    } else {
      b.addByte(1 | 0x20);
      b.addByte(0x21);
      szWriteNum(b, 1);
      b.addByte(f.lzDictProp);
    }
    if (aes) {
      szWriteNum(b, 1);
      szWriteNum(b, 0);
    }
  }

  void _writeStreams(ByteBuilder b, List<_FolderOut> folders, {required bool withSubs, required bool folderCrc, int? headerCrc}) {
    b.addByte(0x06);
    szWriteNum(b, folders.first.startPos - 32);
    szWriteNum(b, folders.length);
    b.addByte(0x09);
    for (final _FolderOut f in folders) {
      szWriteNum(b, f.packSize);
    }
    b.addByte(0x00);
    b.addByte(0x07);
    b.addByte(0x0B);
    szWriteNum(b, folders.length);
    b.addByte(0x00);
    for (final _FolderOut f in folders) {
      _writeFolder(b, f);
    }
    b.addByte(0x0C);
    for (final _FolderOut f in folders) {
      if (f.encrypted) szWriteNum(b, f.coderSize);
      szWriteNum(b, f.unpackSize);
    }
    if (folderCrc && headerCrc != null) {
      b.addByte(0x0A);
      b.addByte(1);
      b.addU32le(headerCrc);
    }
    b.addByte(0x00);
    if (withSubs) {
      b.addByte(0x08);
      b.addByte(0x0D);
      for (final _FolderOut f in folders) {
        szWriteNum(b, f.subs.length);
      }
      b.addByte(0x09);
      for (final _FolderOut f in folders) {
        for (var i = 0; i < f.subs.length - 1; i++) {
          szWriteNum(b, f.subs[i].size);
        }
      }
      b.addByte(0x0A);
      b.addByte(1);
      for (final _FolderOut f in folders) {
        for (final _Sub s in f.subs) {
          b.addU32le(s.crc);
        }
      }
      b.addByte(0x00);
    }
    b.addByte(0x00);
  }

  static Uint8List _bitVector(List<bool> v) {
    final Uint8List out = Uint8List((v.length + 7) ~/ 8);
    for (var i = 0; i < v.length; i++) {
      if (v[i]) out[i >> 3] |= 0x80 >> (i & 7);
    }
    return out;
  }

  Uint8List _buildHeader() {
    final ByteBuilder b = ByteBuilder(1024);
    b.addByte(0x01);
    if (_folders.isNotEmpty) {
      b.addByte(0x04);
      _writeStreams(b, _folders, withSubs: true, folderCrc: false);
    }
    if (_items.isNotEmpty) {
      b.addByte(0x05);
      szWriteNum(b, _items.length);
      final List<bool> es = _items.map((_Item i) => i.emptyStream).toList();
      if (es.contains(true)) {
        final Uint8List v = _bitVector(es);
        b.addByte(0x0E);
        szWriteNum(b, v.length);
        b.addBytes(v);
        final List<bool> ef = _items.where((_Item i) => i.emptyStream).map((_Item i) => i.emptyFile).toList();
        if (ef.contains(true)) {
          final Uint8List v2 = _bitVector(ef);
          b.addByte(0x0F);
          szWriteNum(b, v2.length);
          b.addBytes(v2);
        }
      }
      final ByteBuilder nb = ByteBuilder(256);
      nb.addByte(0);
      for (final _Item i in _items) {
        final String p = i.path;
        for (var k = 0; k < p.length; k++) {
          nb.addU16le(p.codeUnitAt(k));
        }
        nb.addU16le(0);
      }
      b.addByte(0x11);
      szWriteNum(b, nb.length);
      b.addBytes(nb.view());
      final ByteBuilder tb = ByteBuilder(_items.length * 8 + 4);
      tb.addByte(1);
      tb.addByte(0);
      for (final _Item i in _items) {
        tb.addU64le(i.mtime);
      }
      b.addByte(0x14);
      szWriteNum(b, tb.length);
      b.addBytes(tb.view());
      final ByteBuilder ab = ByteBuilder(_items.length * 4 + 4);
      ab.addByte(1);
      ab.addByte(0);
      for (final _Item i in _items) {
        ab.addU32le(i.attrs);
      }
      b.addByte(0x15);
      szWriteNum(b, ab.length);
      b.addBytes(ab.view());
      b.addByte(0x00);
    }
    b.addByte(0x00);
    return b.toBytes();
  }

  @override
  void finishFormat() {
    _closeFolder();
    Uint8List next = Uint8List(0);
    if (_items.isNotEmpty) {
      Uint8List header = _buildHeader();
      final bool encName = options.encryptNames && _key != null;
      if (options.level > 0 || encName) {
        final _FolderOut hf = _FolderOut(
          out: _out,
          level: options.level > 0 ? options.level : 5,
          aesProps: encName ? _aesProps : null,
          aesKey: encName ? _key : null,
          cancel: cancel,
        );
        hf.add(header, 0, header.length);
        hf.close();
        final ByteBuilder e = ByteBuilder(128);
        e.addByte(0x17);
        _writeStreams(e, <_FolderOut>[hf], withSubs: false, folderCrc: true, headerCrc: crc32(header));
        next = e.toBytes();
      } else {
        next = header;
      }
    }
    final int nextPos = _out.position;
    if (next.isNotEmpty) _out.add(next);
    final ByteBuilder sh = ByteBuilder(32);
    sh.addBytes(<int>[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C, 0x00, 0x04]);
    final ByteBuilder tail = ByteBuilder(20);
    tail.addU64le(next.isEmpty ? 0 : nextPos - 32);
    tail.addU64le(next.length);
    tail.addU32le(next.isEmpty ? 0 : crc32(next));
    sh.addU32le(crc32(tail.view()));
    sh.addBytes(tail.view());
    _out.patch(0, sh.toBytes());
    _out.close();
  }

  @override
  void closeRaw() {
    try {
      _out.close();
    } catch (_) {}
  }
}
