import 'dart:typed_data';

import 'errors.dart';
import 'open.dart';
import 'writers.dart';

/// Hooks for the few things `dart:io` cannot do on its own.
class PzHooks {
  /// Called after a file was extracted, with the Unix permission bits stored in
  /// the archive. Set it to apply them, for example with a platform call.
  static void Function(String path, int mode)? chmod;
}

/// The archive formats pzip knows.
enum ArchiveFormat {
  /// A zip archive (zip64 for big files).
  zip,

  /// An uncompressed tar archive.
  tar,

  /// A tar archive compressed with gzip (`.tar.gz`).
  tarGz,

  /// A tar archive compressed with xz (`.tar.xz`).
  tarXz,

  /// A 7z archive.
  sevenZip,

  /// A single file compressed with gzip (`notes.txt.gz`). Read only, one entry.
  gzip,

  /// A single file compressed with xz. Read only, one entry.
  xz,
}

/// One item inside an archive.
class PzEntry {
  const PzEntry({
    required this.path,
    required this.isDir,
    required this.size,
    required this.packedSize,
    this.modified,
    this.mode,
    this.encrypted = false,
    this.linkTarget,
  });

  /// The path inside the archive: `/` separated, with no leading or trailing
  /// `/` (also for folders).
  final String path;

  /// Whether this entry is a folder.
  final bool isDir;

  /// The uncompressed size in bytes (0 for folders).
  final int size;

  /// The compressed size in bytes, or -1 when the format cannot tell per entry
  /// (solid 7z blocks, tar.gz and tar.xz).
  final int packedSize;

  /// When the entry was last changed, if the archive stores it.
  final DateTime? modified;

  /// The Unix permission bits (for example `0x1ED` for 0755), if stored.
  final int? mode;

  /// Whether the entry's data is encrypted.
  final bool encrypted;

  /// Where the entry points to when it is a symbolic link, otherwise null.
  final String? linkTarget;
}

/// How [ArchiveWriter.create] should write an archive.
class WriteOptions {
  const WriteOptions({
    this.level = 5,
    this.password,
    this.encryptNames = false,
    this.keepPermissions = true,
    this.solid = true,
  });

  /// The compression level: 0 stores without compression, 1 to 3 are fast,
  /// 4 to 6 normal and 7 to 9 maximum. Plain tar has no compression and ignores
  /// it; tar.gz and tar.xz use it for their codec.
  final int level;

  /// A password. Zip uses WinZip AES-256 and 7z uses 7zAES (AES-256 with a
  /// SHA-256 key derivation). The tar formats do not support passwords, and
  /// [ArchiveWriter.create] throws [PzUnsupported] for them.
  final String? password;

  /// 7z only: also encrypt the list of file names. Needs [password].
  final bool encryptNames;

  /// Store the Unix permission bits where the format can (zip, tar and 7z).
  final bool keepPermissions;

  /// 7z only: pack all files into one compressed block. This gives the best
  /// ratio, but reading one file then decompresses the ones before it. When
  /// false every file is packed on its own, so single files read quickly.
  final bool solid;
}

/// Writes one archive. Add entries one by one, then call [close].
///
/// ```dart
/// final writer = await ArchiveWriter.create(
///   'x.7z',
///   ArchiveFormat.sevenZip,
///   options: const WriteOptions(level: 5, password: 'secret'),
/// );
/// await writer.addDirectory('lib');
/// await writer.addFile('dev/lib/a.dart', 'lib/a.dart');
/// await writer.close();
/// ```
abstract class ArchiveWriter {
  /// Creates the file at [outPath], replacing any file that is there.
  ///
  /// [onProgress] receives the number of input bytes just consumed, many times
  /// per file. A single gzip or xz file cannot be written on its own: use
  /// [ArchiveFormat.tarGz] or [ArchiveFormat.tarXz].
  static Future<ArchiveWriter> create(
    String outPath,
    ArchiveFormat format, {
    WriteOptions options = const WriteOptions(),
    void Function(int bytes)? onProgress,
    CancelToken? cancel,
  }) =>
      createArchiveWriter(outPath, format, options, onProgress, cancel);

  /// Adds the file at [diskPath] under [archivePath] (relative, `/` separated).
  /// The modified time and permissions are read from the file.
  Future<void> addFile(String diskPath, String archivePath);

  /// Adds an empty folder entry. It is only needed for folders with no files in
  /// them.
  Future<void> addDirectory(String archivePath, {DateTime? modified, int? mode});

  /// Adds a file whose content is [bytes] under [archivePath].
  Future<void> addBytes(String archivePath, Uint8List bytes, {DateTime? modified});

  /// Adds a symbolic link entry that points to [target] (zip, tar and 7z).
  Future<void> addSymlink(String archivePath, String target);

  /// Finishes the archive: writes the index and closes the file.
  Future<void> close();

  /// Closes the writer and deletes the unfinished output file. Safe to call
  /// after [close].
  Future<void> abort();
}

/// Reads an archive without unpacking all of it.
abstract class ArchiveReader {
  /// Opens the archive at [path].
  ///
  /// Throws [PzPasswordRequired] when the names are encrypted and [password] is
  /// missing, [PzWrongPassword] when it does not fit, [PzUnsupported] for
  /// formats or methods pzip cannot read (RAR, for example) and [PzCorrupt] for
  /// damaged files. A zip or 7z whose names are readable but whose data is
  /// encrypted opens normally: check [PzEntry.encrypted] and pass [password] to
  /// read the data.
  static Future<ArchiveReader> open(
    String path, {
    String? password,
    CancelToken? cancel,
  }) =>
      openArchive(path, password, cancel);

  /// Looks at the first bytes (and the file name) to tell the format. Returns
  /// null when it is not known.
  static Future<ArchiveFormat?> detect(String path) => detectArchiveFormat(path);

  /// The format of this archive.
  ArchiveFormat get format;

  /// Every entry, files and folders, in archive order. Zip and 7z read this
  /// from their index, so listing is fast. Tar.gz and tar.xz are decompressed
  /// once while opening.
  List<PzEntry> get entries;

  /// Whether any entry is encrypted.
  bool get hasEncryptedEntries;

  /// Whether the whole archive is one solid block (7z, tar.gz, tar.xz), where
  /// reading one file may have to decompress the ones before it.
  bool get isSolid;

  /// Writes [entry] to the file [destPath], creating parent folders and
  /// restoring the modified time.
  ///
  /// Throws [PzWrongPassword] for a bad password (zip notices at once, 7z at
  /// the final CRC check) and [PzCorrupt] for a bad CRC. [onProgress] receives
  /// the number of output bytes just written.
  Future<void> extractEntry(
    PzEntry entry,
    String destPath, {
    void Function(int bytes)? onProgress,
    CancelToken? cancel,
  });

  /// Streams the bytes of [entry], for a preview or for hashing. It throws the
  /// same errors as [extractEntry]. The entry is decoded without waiting for
  /// the listener, so prefer [extractTo] for big entries in solid archives.
  Stream<List<int>> openRead(PzEntry entry);

  /// Decodes [entry] and hands each piece to [sink] as it is produced. The
  /// buffer is only valid during the call. Throws the same errors as
  /// [extractEntry].
  Future<void> extractTo(
    PzEntry entry,
    void Function(Uint8List chunk) sink, {
    CancelToken? cancel,
  });

  /// Reads [entry] fully into memory. Throws [PzException] when it is larger
  /// than [maxBytes] (16 MiB by default).
  Future<Uint8List> readBytes(PzEntry entry, {int maxBytes = 16 * 1024 * 1024});

  /// Extracts everything, or only what [filter] accepts, below [destDir] in one
  /// pass (solid archives are decompressed once).
  ///
  /// Names that would leave [destDir] (`../` or absolute paths) are skipped and
  /// listed in the returned list. Symbolic links are created with `dart:io`;
  /// a link that cannot be created is skipped. [onFile] is called as each entry
  /// starts.
  Future<List<String>> extractAll(
    String destDir, {
    bool Function(PzEntry entry)? filter,
    void Function(PzEntry entry)? onFile,
    void Function(int bytes)? onProgress,
    CancelToken? cancel,
  });

  /// Closes the archive file.
  Future<void> close();
}
