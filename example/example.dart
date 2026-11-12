import 'dart:io';

import 'package:pzip/pzip.dart';

Future<void> main() async {
  final Directory work = await Directory.systemTemp.createTemp('pzip_example_');
  try {
    final String source = '${work.path}/source';
    await Directory('$source/notes').create(recursive: true);
    await File('$source/hello.txt').writeAsString('Hello from pzip.\n');
    await File('$source/notes/todo.txt').writeAsString('1. publish\n2. relax\n');

    final String zip = await _pack(work.path, source, 'demo.zip', ArchiveFormat.zip);
    await _list(zip);

    final String tar = await _pack(work.path, source, 'demo.tar.gz', ArchiveFormat.tarGz);
    await _list(tar);

    final String sevenZip = await _pack(
      work.path,
      source,
      'demo.7z',
      ArchiveFormat.sevenZip,
      password: 'secret',
    );
    await _list(sevenZip, password: 'secret');

    await _extract(sevenZip, '${work.path}/out', password: 'secret');
    stdout.writeln(await File('${work.path}/out/notes/todo.txt').readAsString());

    await _wrongPassword(sevenZip);
  } finally {
    await work.delete(recursive: true);
  }
}

Future<String> _pack(
  String dir,
  String source,
  String name,
  ArchiveFormat format, {
  String? password,
}) async {
  final String out = '$dir/$name';
  final ArchiveWriter writer = await ArchiveWriter.create(
    out,
    format,
    options: WriteOptions(level: 6, password: password),
  );
  await writer.addFile('$source/hello.txt', 'hello.txt');
  await writer.addDirectory('notes');
  await writer.addFile('$source/notes/todo.txt', 'notes/todo.txt');
  await writer.close();
  stdout.writeln('Created $name (${File(out).lengthSync()} bytes)');
  return out;
}

Future<void> _list(String path, {String? password}) async {
  final ArchiveReader reader = await ArchiveReader.open(path, password: password);
  try {
    stdout.writeln('${reader.format.name}: ${reader.entries.length} entries');
    for (final PzEntry entry in reader.entries) {
      final String kind = entry.isDir ? 'dir ' : 'file';
      stdout.writeln('  $kind ${entry.path} (${entry.size} bytes)');
    }
  } finally {
    await reader.close();
  }
}

Future<void> _extract(String path, String destination, {String? password}) async {
  final ArchiveReader reader = await ArchiveReader.open(path, password: password);
  try {
    final List<String> written = await reader.extractAll(
      destination,
      onFile: (PzEntry entry) => stdout.writeln('Extracting ${entry.path}'),
    );
    stdout.writeln('${written.length} items written');
  } finally {
    await reader.close();
  }
}

Future<void> _wrongPassword(String path) async {
  try {
    final ArchiveReader reader = await ArchiveReader.open(path, password: 'nope');
    await reader.close();
    stdout.writeln('The wrong password was not noticed.');
  } on PzWrongPassword {
    stdout.writeln('The wrong password was refused.');
  } on PzPasswordRequired {
    stdout.writeln('A password is needed.');
  }
}
