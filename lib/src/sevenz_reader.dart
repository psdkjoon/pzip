import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'api.dart';
import 'deflate.dart';
import 'errors.dart';
import 'hash.dart';
import 'io.dart';
import 'lzma.dart';
import 'reader_base.dart';
import 'sevenz_common.dart';

class SzCoder {
  SzCoder(this.id, this.nin, this.nout, this.props);

  final String id;
  final int nin;
  final int nout;
  final Uint8List props;
}

class SzFolder {
  final List<SzCoder> coders = <SzCoder>[];
  final List<int> bindIn = <int>[];
  final List<int> bindOut = <int>[];
  List<int> packed = <int>[];
  List<int> sizes = <int>[];
  int? crc;

  int packStart = 0;

  int get totalOut {
    var n = 0;
    for (final SzCoder c in coders) {
      n += c.nout;
    }
    return n;
  }

  int get mainOut {
    for (var i = 0; i < totalOut; i++) {
      if (!bindOut.contains(i)) return i;
    }
    throw const PzCorrupt('The 7z header is damaged.');
  }

  int get unpackSize => sizes[mainOut];

  bool get encrypted => coders.any((SzCoder c) => c.id == '06f10701');

  List<int> chain() {
    for (final SzCoder c in coders) {
      if (c.nin != 1 || c.nout != 1) {
        throw const PzUnsupported('This 7z file uses a coder pzip cannot read.');
      }
    }
    if (packed.length != 1) throw const PzUnsupported('This 7z file uses a coder pzip cannot read.');
    final List<int> out = <int>[];
    var idx = packed[0];
    for (var guard = 0; guard <= coders.length; guard++) {
      out.add(idx);
      if (idx == mainOut) return out;
      final int k = bindOut.indexOf(idx);
      if (k < 0) break;
      idx = bindIn[k];
    }
    throw const PzCorrupt('The 7z header is damaged.');
  }
}

class _Streams {
  int packPos = 0;
  List<int> packSizes = <int>[];
  final List<SzFolder> folders = <SzFolder>[];
  List<int> nums = <int>[];
  List<int> sizes = <int>[];
  List<int?> crcs = <int?>[];
}

class _SzFile {
  _SzFile(this.folder, this.size, this.crc);

  final int folder;
  final int size;
  final int? crc;
}

class SevenZReader extends ReaderBase {
  SevenZReader._(super.path, this._raf, this._len, this._password);

  final RandomAccessFile _raf;
  final int _len;
  final String? _password;
  final List<PzEntry> _entries = <PzEntry>[];
  final Map<PzEntry, _SzFile> _file = Map<PzEntry, _SzFile>.identity();
  final List<SzFolder> _folders = <SzFolder>[];
  final List<List<PzEntry>> _folderFiles = <List<PzEntry>>[];
  List<int> _packSizes = <int>[];
  int _packPos = 0;
  bool _hasEncrypted = false;

  static SevenZReader open(String path, String? password) {
    final RandomAccessFile raf = File(path).openSync();
    final SevenZReader r = SevenZReader._(path, raf, raf.lengthSync(), password);
    try {
      r._load();
    } catch (_) {
      raf.closeSync();
      rethrow;
    }
    return r;
  }

  Uint8List _readAt(int pos, int n) {
    _raf.setPositionSync(pos);
    final Uint8List b = Uint8List(n);
    var got = 0;
    while (got < n) {
      final int r = _raf.readIntoSync(b, got, n);
      if (r <= 0) throw const PzCorrupt('The file ends too early.');
      got += r;
    }
    return b;
  }

  void _load() {
    if (_len < 32) throw const PzCorrupt('This is not a 7z file.');
    final Uint8List sh = _readAt(0, 32);
    const List<int> sig = <int>[0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
    for (var i = 0; i < 6; i++) {
      if (sh[i] != sig[i]) throw const PzCorrupt('This is not a 7z file.');
    }
    if (sh[6] != 0) throw const PzUnsupported('This 7z version is not supported.');
    final SzReader r = SzReader(sh, 8);
    final int startCrc = r.u32();
    if (crc32(sh, 12, 32) != startCrc) throw const PzCorrupt('The 7z header is damaged.');
    final int off = r.u64();
    final int size = r.u64();
    final int hcrc = r.u32();
    if (size == 0) return;
    if (off < 0 || size < 0 || size > (1 << 28) || 32 + off + size > _len) {
      throw const PzCorrupt('The 7z header is damaged.');
    }
    var hdr = _readAt(32 + off, size);
    if (crc32(hdr) != hcrc) throw const PzCorrupt('The 7z header is damaged.');
    while (true) {
      final SzReader s = SzReader(hdr);
      final int t = s.byte();
      if (t == 1) {
        _parseHeader(s);
        return;
      }
      if (t != 0x17) throw const PzCorrupt('The 7z header is damaged.');
      final _Streams st = _readStreams(s);
      if (st.folders.isEmpty) throw const PzCorrupt('The 7z header is damaged.');
      final SzFolder f = st.folders[0];
      _assignPackStarts(st);
      final ByteBuilder out = ByteBuilder(f.unpackSize < 16 ? 16 : f.unpackSize);
      try {
        _decodeFolderInto(f, st.packPos, st.packSizes, (Uint8List b, int s2, int e) => out.addBytes(b, s2, e), null);
      } on PzCorrupt {
        if (f.encrypted) throw const PzWrongPassword();
        rethrow;
      }
      hdr = out.toBytes();
      if (f.crc != null && crc32(hdr) != f.crc) {
        if (f.encrypted) throw const PzWrongPassword();
        throw const PzCorrupt('The 7z header is damaged.');
      }
    }
  }

  void _assignPackStarts(_Streams st) {
    var k = 0;
    for (final SzFolder f in st.folders) {
      f.packStart = k;
      k += f.packed.length;
    }
  }

  _Streams _readStreams(SzReader s) {
    final _Streams st = _Streams();
    while (true) {
      final int t = s.byte();
      if (t == 0) break;
      if (t == 6) {
        st.packPos = s.num();
        final int n = s.num();
        while (true) {
          final int t2 = s.byte();
          if (t2 == 0) break;
          if (t2 == 9) {
            st.packSizes = List<int>.generate(n, (int _) => s.num());
          } else if (t2 == 0x0A) {
            s.digests(n);
          } else {
            throw const PzCorrupt('The 7z header is damaged.');
          }
        }
      } else if (t == 7) {
        if (s.byte() != 0x0B) throw const PzCorrupt('The 7z header is damaged.');
        final int nf = s.num();
        if (s.byte() != 0) throw const PzUnsupported('This 7z file is not supported.');
        for (var i = 0; i < nf; i++) {
          final SzFolder f = SzFolder();
          final int nc = s.num();
          var tin = 0;
          var tout = 0;
          for (var c = 0; c < nc; c++) {
            final int fl = s.byte();
            if ((fl & 0x80) != 0) throw const PzUnsupported('This 7z file is not supported.');
            final Uint8List id = s.bytes(fl & 15);
            var nin = 1;
            var nout = 1;
            if ((fl & 0x10) != 0) {
              nin = s.num();
              nout = s.num();
            }
            Uint8List props = Uint8List(0);
            if ((fl & 0x20) != 0) {
              props = Uint8List.fromList(s.bytes(s.num()));
            }
            tin += nin;
            tout += nout;
            f.coders.add(SzCoder(toHexString(id), nin, nout, props));
          }
          for (var b = 0; b < tout - 1; b++) {
            f.bindIn.add(s.num());
            f.bindOut.add(s.num());
          }
          final int npk = tin - (tout - 1);
          if (npk == 1) {
            for (var k = 0; k < tin; k++) {
              if (!f.bindIn.contains(k)) {
                f.packed = <int>[k];
                break;
              }
            }
          } else {
            f.packed = List<int>.generate(npk, (int _) => s.num());
          }
          st.folders.add(f);
        }
        if (s.byte() != 0x0C) throw const PzCorrupt('The 7z header is damaged.');
        for (final SzFolder f in st.folders) {
          f.sizes = List<int>.generate(f.totalOut, (int _) => s.num());
        }
        while (true) {
          final int t2 = s.byte();
          if (t2 == 0) break;
          if (t2 == 0x0A) {
            final List<int?> d = s.digests(nf);
            for (var i = 0; i < nf; i++) {
              st.folders[i].crc = d[i];
            }
          } else {
            throw const PzCorrupt('The 7z header is damaged.');
          }
        }
      } else if (t == 8) {
        _readSub(s, st);
      } else {
        throw const PzCorrupt('The 7z header is damaged.');
      }
    }
    if (st.nums.isEmpty && st.folders.isNotEmpty) {
      st.nums = List<int>.filled(st.folders.length, 1);
      st.sizes = st.folders.map((SzFolder f) => f.unpackSize).toList();
      st.crcs = st.folders.map((SzFolder f) => f.crc).toList();
    }
    return st;
  }

  void _readSub(SzReader s, _Streams st) {
    final List<SzFolder> folders = st.folders;
    var nums = List<int>.filled(folders.length, 1);
    var t = s.byte();
    if (t == 0x0D) {
      nums = List<int>.generate(folders.length, (int _) => s.num());
      t = s.byte();
    }
    final List<int> sizes = <int>[];
    if (t == 9) {
      for (var i = 0; i < folders.length; i++) {
        final int n = nums[i];
        if (n == 0) continue;
        var tot = 0;
        for (var k = 0; k < n - 1; k++) {
          final int v = s.num();
          sizes.add(v);
          tot += v;
        }
        sizes.add(folders[i].unpackSize - tot);
      }
      t = s.byte();
    } else {
      for (var i = 0; i < folders.length; i++) {
        if (nums[i] == 1) {
          sizes.add(folders[i].unpackSize);
        } else if (nums[i] > 1) {
          throw const PzCorrupt('The 7z header is damaged.');
        }
      }
    }
    var need = 0;
    for (var i = 0; i < folders.length; i++) {
      if (!(nums[i] == 1 && folders[i].crc != null)) need += nums[i];
    }
    List<int?>? crcs;
    while (t != 0) {
      if (t == 0x0A) {
        final List<int?> ds = s.digests(need);
        crcs = <int?>[];
        var k = 0;
        for (var i = 0; i < folders.length; i++) {
          if (nums[i] == 1 && folders[i].crc != null) {
            crcs.add(folders[i].crc);
          } else {
            for (var j = 0; j < nums[i]; j++) {
              crcs.add(ds[k++]);
            }
          }
        }
      } else {
        throw const PzCorrupt('The 7z header is damaged.');
      }
      t = s.byte();
    }
    if (crcs == null) {
      crcs = <int?>[];
      for (var i = 0; i < folders.length; i++) {
        if (nums[i] == 1 && folders[i].crc != null) {
          crcs.add(folders[i].crc);
        } else {
          for (var j = 0; j < nums[i]; j++) {
            crcs.add(null);
          }
        }
      }
    }
    st.nums = nums;
    st.sizes = sizes;
    st.crcs = crcs;
  }

  void _parseHeader(SzReader s) {
    _Streams? st;
    var numFiles = 0;
    List<String> names = <String>[];
    List<bool>? emptyStream;
    List<bool>? emptyFile;
    List<int?>? attrs;
    List<int?>? mtimes;
    while (true) {
      final int t = s.byte();
      if (t == 0) break;
      if (t == 2) {
        while (s.byte() != 0) {
          s.skip(s.num());
        }
      } else if (t == 3) {
        throw const PzUnsupported('This 7z file is not supported.');
      } else if (t == 4) {
        st = _readStreams(s);
      } else if (t == 5) {
        numFiles = s.num();
        while (true) {
          final int pt = s.byte();
          if (pt == 0) break;
          final int sz = s.num();
          final int end = s.p + sz;
          if (end > s.end) throw const PzCorrupt('The 7z header is damaged.');
          if (pt == 0x0E) {
            emptyStream = s.bits(numFiles);
          } else if (pt == 0x0F) {
            var ne = 0;
            for (final bool b in emptyStream ?? <bool>[]) {
              if (b) ne++;
            }
            emptyFile = s.bits(ne);
          } else if (pt == 0x11) {
            if (s.byte() != 0) throw const PzUnsupported('This 7z file is not supported.');
            final Uint8List raw = s.bytes(end - s.p);
            final List<int> units = <int>[];
            final List<String> list = <String>[];
            for (var i = 0; i + 1 < raw.length; i += 2) {
              final int u = raw[i] | (raw[i + 1] << 8);
              if (u == 0) {
                list.add(String.fromCharCodes(units));
                units.clear();
              } else {
                units.add(u);
              }
            }
            names = list;
          } else if (pt == 0x15) {
            final List<bool> d = s.defined(numFiles);
            if (s.byte() != 0) throw const PzUnsupported('This 7z file is not supported.');
            attrs = List<int?>.generate(numFiles, (int i) => d[i] ? s.u32() : null);
          } else if (pt == 0x14) {
            final List<bool> d = s.defined(numFiles);
            if (s.byte() != 0) throw const PzUnsupported('This 7z file is not supported.');
            mtimes = List<int?>.generate(numFiles, (int i) => d[i] ? s.u64() : null);
          }
          s.p = end;
        }
      } else {
        throw const PzCorrupt('The 7z header is damaged.');
      }
    }
    if (numFiles == 0) return;
    if (names.length < numFiles) throw const PzCorrupt('The 7z header is damaged.');
    if (st != null) {
      _assignPackStarts(st);
      _folders.addAll(st.folders);
      _packSizes = st.packSizes;
      _packPos = st.packPos;
      for (var i = 0; i < _folders.length; i++) {
        _folderFiles.add(<PzEntry>[]);
      }
    }
    final List<int> subFolder = <int>[];
    if (st != null) {
      for (var i = 0; i < st.folders.length; i++) {
        for (var k = 0; k < st.nums[i]; k++) {
          subFolder.add(i);
        }
      }
    }
    var si = 0;
    var ek = 0;
    final List<PzEntry> links = <PzEntry>[];
    for (var i = 0; i < numFiles; i++) {
      final bool isEmpty = emptyStream != null && emptyStream[i];
      var rel = names[i].replaceAll('\\', '/');
      while (rel.startsWith('/')) {
        rel = rel.substring(1);
      }
      while (rel.endsWith('/')) {
        rel = rel.substring(0, rel.length - 1);
      }
      final int? at = attrs?[i];
      final int? ft = mtimes?[i];
      DateTime? modified;
      if (ft != null && ft > 0) {
        modified = DateTime.fromMicrosecondsSinceEpoch((ft - 116444736000000000) ~/ 10);
      }
      int? mode;
      var type = 0;
      if (at != null && (at & 0x8000) != 0) {
        mode = (at >> 16) & 0xFFF;
        type = (at >> 16) & 0xF000;
      }
      bool isDir;
      var size = 0;
      int? crc;
      var folder = -1;
      if (isEmpty) {
        final bool isFile = emptyFile != null && ek < emptyFile.length && emptyFile[ek];
        ek++;
        isDir = !isFile;
      } else {
        if (st == null || si >= subFolder.length) throw const PzCorrupt('The 7z header is damaged.');
        isDir = false;
        size = st.sizes[si];
        crc = st.crcs[si];
        folder = subFolder[si];
        si++;
      }
      if (at != null && (at & 0x10) != 0 && isEmpty) isDir = true;
      if (rel.isEmpty) {
        if (folder < 0) continue;
        rel = '_';
      }
      final bool enc = folder >= 0 && _folders[folder].encrypted;
      if (enc) _hasEncrypted = true;
      final PzEntry e = PzEntry(
        path: rel,
        isDir: isDir,
        size: size,
        packedSize: (folder >= 0 && _folders[folder].packed.length == 1 && st!.nums[folder] == 1)
            ? _packSizes[_folders[folder].packStart]
            : -1,
        modified: modified,
        mode: mode,
        encrypted: enc,
      );
      _entries.add(e);
      if (folder >= 0) {
        _file[e] = _SzFile(folder, size, crc);
        _folderFiles[folder].add(e);
        if (type == 0xA000 && size < 4096 && !enc) links.add(e);
      } else {
        _file[e] = _SzFile(-1, 0, null);
      }
    }
    if (links.isNotEmpty) {
      final Map<PzEntry, String> targets = Map<PzEntry, String>.identity();
      try {
        final Map<PzEntry, ByteBuilder> bufs = Map<PzEntry, ByteBuilder>.identity();
        decodeMany(links, (PzEntry e) {
          final ByteBuilder b = ByteBuilder(32);
          bufs[e] = b;
          return (Uint8List x, int a, int c) => b.addBytes(x, a, c);
        }, (PzEntry e) {
          targets[e] = utf8.decode(bufs[e]!.view(), allowMalformed: true);
        }, null);
      } catch (_) {
      }
      for (var i = 0; i < _entries.length; i++) {
        final PzEntry e = _entries[i];
        final String? t = targets[e];
        if (t == null) continue;
        final PzEntry n = PzEntry(
          path: e.path,
          isDir: false,
          size: e.size,
          packedSize: e.packedSize,
          modified: e.modified,
          mode: e.mode,
          encrypted: false,
          linkTarget: t,
        );
        _entries[i] = n;
        final _SzFile f = _file.remove(e)!;
        _file[n] = f;
        final List<PzEntry> ff = _folderFiles[f.folder];
        ff[ff.indexOf(e)] = n;
      }
    }
  }

  @override
  ArchiveFormat get format => ArchiveFormat.sevenZip;

  @override
  List<PzEntry> get entries => _entries;

  @override
  bool get hasEncryptedEntries => _hasEncrypted;

  @override
  bool get isSolid => _folderFiles.any((List<PzEntry> l) => l.length > 1);

  @override
  Future<void> close() async {
    try {
      _raf.closeSync();
    } catch (_) {}
  }

  void _decodeFolderInto(
    SzFolder f,
    int packPos,
    List<int> packSizes,
    ChunkSink sink,
    CancelToken? cancel,
  ) {
    final List<int> chain = f.chain();
    var start = 32 + packPos;
    for (var i = 0; i < f.packStart; i++) {
      start += packSizes[i];
    }
    final int psize = packSizes[f.packStart];
    if (start + psize > _len) throw const PzCorrupt('The file ends too early.');
    ByteInput input = FileInput(_raf, start, start + psize);
    var inSize = psize;
    var decoded = false;
    final int finalSize = f.unpackSize;
    var produced = 0;
    void out(Uint8List b, int s, int e) {
      produced += e - s;
      sink(b, s, e);
    }

    for (final int idx in chain) {
      final SzCoder c = f.coders[idx];
      final int usz = f.sizes[idx];
      switch (c.id) {
        case '06f10701':
          if (decoded) throw const PzUnsupported('This 7z file is not supported.');
          final String? pw = _password;
          if (pw == null) throw const PzPasswordRequired();
          final Uint8List p = c.props;
          if (p.isEmpty) throw const PzCorrupt('The 7z header is damaged.');
          final int b0 = p[0];
          final int b1 = p.length > 1 ? p[1] : 0;
          final int saltSize = ((b0 >> 7) & 1) + (b1 >> 4);
          final int ivSize = ((b0 >> 6) & 1) + (b1 & 15);
          if (p.length < 2 + saltSize + ivSize || ivSize > 16) {
            throw const PzCorrupt('The 7z header is damaged.');
          }
          final Uint8List salt = Uint8List.sublistView(p, 2, 2 + saltSize);
          final Uint8List iv = Uint8List(16)..setRange(0, ivSize, p, 2 + saltSize);
          final Uint8List key = sevenZipKey(salt, b0 & 63, pw);
          input = AesCbcInput(input, key, iv, usz);
          inSize = usz;
          break;
        case '00':
          decoded = true;
          _copy(input, usz, out, cancel);
          break;
        case '030101':
          decoded = true;
          lzmaDecode(input, c.props, usz, out, cancel: cancel);
          break;
        case '21':
          if (c.props.isEmpty) throw const PzCorrupt('The 7z header is damaged.');
          decoded = true;
          lzma2Decode(input, c.props[0], out, cap: usz, cancel: cancel);
          break;
        case '040108':
          decoded = true;
          inflateRaw(input, inSize, out, cancel: cancel);
          break;
        default:
          throw PzUnsupported('The 7z method ${c.id} is not supported.');
      }
    }
    if (produced != finalSize) throw const PzCorrupt('The 7z data has the wrong size.');
  }

  static void _copy(ByteInput input, int size, ChunkSink out, CancelToken? cancel) {
    final Uint8List buf = Uint8List(65536);
    var left = size;
    while (left > 0) {
      if (cancel != null && cancel.isCancelled) throw const PzCancelled();
      final int n = input.read(buf, 0, left < buf.length ? left : buf.length);
      if (n <= 0) throw const PzCorrupt('The file ends too early.');
      out(buf, 0, n);
      left -= n;
    }
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
    final Map<int, Set<PzEntry>> byFolder = <int, Set<PzEntry>>{};
    for (final PzEntry e in wanted) {
      final _SzFile? f = _file[e];
      if (f == null) throw const PzException('Not an entry of this archive.');
      if (f.folder < 0) {
        final ChunkSink? s = open(e);
        if (s != null) close(e);
      } else {
        byFolder.putIfAbsent(f.folder, () => Set<PzEntry>.identity()).add(e);
      }
    }
    final List<int> order = byFolder.keys.toList()..sort();
    for (final int fi in order) {
      if (cancel != null && cancel.isCancelled) throw const PzCancelled();
      _runFolder(fi, byFolder[fi]!, open, close, cancel);
    }
  }

  void _runFolder(
    int fi,
    Set<PzEntry> want,
    EntryOpener open,
    EntryCloser close,
    CancelToken? cancel,
  ) {
    final SzFolder folder = _folders[fi];
    final List<PzEntry> files = _folderFiles[fi];
    var last = -1;
    for (var i = 0; i < files.length; i++) {
      if (want.contains(files[i])) last = i;
    }
    if (last < 0) return;
    var cur = 0;
    var started = false;
    var remaining = 0;
    ChunkSink? sink;
    Crc32? crc;

    void finish() {
      final PzEntry e = files[cur];
      if (sink != null) {
        final int? expect = _file[e]!.crc;
        if (expect != null && crc!.value != expect) {
          if (folder.encrypted) throw const PzWrongPassword();
          throw const PzCorrupt('The 7z data is damaged (bad checksum).');
        }
        sink = null;
        close(e);
      }
      final bool wasLast = cur == last;
      cur++;
      started = false;
      if (wasLast) throw const PzStop();
    }

    void begin() {
      final PzEntry e = files[cur];
      started = true;
      remaining = _file[e]!.size;
      if (want.contains(e)) {
        sink = open(e);
        crc = Crc32();
      }
    }

    void feed(Uint8List b, int s, int e) {
      var i = s;
      while (true) {
        if (cur >= files.length) {
          if (i < e) throw const PzCorrupt('The 7z data has the wrong size.');
          return;
        }
        if (!started) begin();
        if (remaining == 0) {
          finish();
          continue;
        }
        if (i >= e) return;
        final int n = remaining < (e - i) ? remaining : (e - i);
        final ChunkSink? sk = sink;
        if (sk != null) {
          sk(b, i, i + n);
          crc!.add(Uint8List.sublistView(b, i, i + n));
        }
        i += n;
        remaining -= n;
        if (remaining == 0) finish();
      }
    }

    try {
      try {
        _decodeFolderInto(folder, _packPos, _packSizes, feed, cancel);
        feed(Uint8List(0), 0, 0);
      } on PzCorrupt {
        if (folder.encrypted) throw const PzWrongPassword();
        rethrow;
      }
    } on PzStop {
    }
  }
}
