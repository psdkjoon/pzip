import 'dart:io';

import 'api.dart';
import 'errors.dart';
import 'gzip.dart';
import 'io.dart';
import 'sevenz_writer.dart';
import 'tar.dart';
import 'xz.dart';
import 'zip_writer.dart';

Future<ArchiveWriter> createArchiveWriter(
  String outPath,
  ArchiveFormat format,
  WriteOptions options,
  void Function(int bytes)? onProgress,
  CancelToken? cancel,
) async {
  final Directory parent = File(outPath).parent;
  if (!parent.existsSync()) parent.createSync(recursive: true);
  switch (format) {
    case ArchiveFormat.zip:
      return ZipWriter.create(outPath, options, onProgress, cancel);
    case ArchiveFormat.sevenZip:
      return SevenZWriter.create(outPath, options, onProgress, cancel);
    case ArchiveFormat.tar:
    case ArchiveFormat.tarGz:
    case ArchiveFormat.tarXz:
      if (options.password != null) {
        throw const PzUnsupported('tar archives cannot have a password.');
      }
      final BufferedOut out = BufferedOut(File(outPath).openSync(mode: FileMode.write));
      final int level = options.level < 1 ? 1 : (options.level > 9 ? 9 : options.level);
      final DataSink sink = format == ArchiveFormat.tar
          ? PlainSink(out)
          : (format == ArchiveFormat.tarGz ? GzSink(out, level) : XzSink(out, level));
      return TarWriter(outPath, options, onProgress, cancel, sink);
    case ArchiveFormat.gzip:
    case ArchiveFormat.xz:
      throw const PzUnsupported('Use tar.gz or tar.xz to write these.');
  }
}
