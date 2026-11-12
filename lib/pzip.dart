/// Pure Dart archives and hashes.
///
/// Read and write zip, tar, tar.gz, tar.xz and 7z archives (with AES
/// passwords where the format has them), read single-file gzip and xz, and use
/// the hashes and ciphers the archives are built on: SHA-1, SHA-256, MD5,
/// CRC-32, HMAC, PBKDF2 and AES.
///
/// There are no dependencies, no Flutter and no platform channels, so
/// everything can run inside an isolate.
///
/// ```dart
/// final reader = await ArchiveReader.open('backup.zip', password: 'secret');
/// await reader.extractAll('out');
/// await reader.close();
/// ```
library pzip;

export 'src/aes.dart' show AesCtr, aesCbcEncrypt, aesCbcDecrypt;
export 'src/api.dart';
export 'src/errors.dart';
export 'src/hash.dart';
