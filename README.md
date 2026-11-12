# pzip

Read and write archives in plain Dart. No dependencies, no Flutter, no platform
channels, no native code, so it also runs inside an isolate.

| Format | Read | Write | Password |
|---|---|---|---|
| zip (zip64) | yes | yes | read: AES and old ZipCrypto; write: AES-256 |
| 7z | LZMA, LZMA2, Deflate, Copy | LZMA2 or Copy, solid or per file | 7zAES, also for names |
| tar, tar.gz, tar.xz | yes | yes | no |
| gzip, xz (single file) | yes | no (use tar.gz or tar.xz) | no |

Not supported: RAR, bzip2, 7z filters such as BCJ, multi-volume archives, gzip
files made of several members.

The package also exposes the hashes and ciphers it is built on: `sha1`,
`sha256`, `md5`, `crc32`, `hmacSha1`, `hmacSha256`, `pbkdf2HmacSha1`,
`pbkdf2HmacSha256`, `AesCtr`, `aesCbcEncrypt` and `aesCbcDecrypt`.

## Install

```sh
dart pub add pzip
```

or in `pubspec.yaml`:

```yaml
dependencies:
  pzip: ^1.0.0
```

## Create an archive

```dart
import 'package:pzip/pzip.dart';

final writer = await ArchiveWriter.create(
  'backup.zip',
  ArchiveFormat.zip,
  options: const WriteOptions(level: 6, password: 'secret'),
);
await writer.addFile('notes/todo.txt', 'todo.txt');
await writer.addDirectory('photos');
await writer.close();
```

`ArchiveFormat.sevenZip`, `tar`, `tarGz` and `tarXz` work the same way. With
`encryptNames: true` a 7z archive hides its file names as well.

## Read an archive

```dart
final reader = await ArchiveReader.open('backup.zip', password: 'secret');
for (final entry in reader.entries) {
  print('${entry.path}  ${entry.size} bytes');
}
await reader.extractAll('out');
await reader.close();
```

A missing or wrong password throws `PzPasswordRequired` or `PzWrongPassword`.
`ArchiveReader.detect(path)` tells which format a file is.

## Hashes

```dart
import 'dart:convert';
import 'package:pzip/pzip.dart';

print(toHexString(sha256(utf8.encode('hello'))));
```

See the `example` folder for complete programs.

## Notes

Work is done with blocking file calls, so run big archives in an isolate. A
`CancelToken` is checked between entries and chunks; to stop at once, kill the
isolate. Set `PzHooks.chmod` if extracted files should get their stored
permissions (the package itself never touches platform code).
