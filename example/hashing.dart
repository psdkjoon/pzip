import 'dart:convert';
import 'dart:typed_data';

import 'package:pzip/pzip.dart';

void main() {
  final Uint8List data = Uint8List.fromList(utf8.encode('hello'));

  print('sha256 ${toHexString(sha256(data))}');
  print('sha1   ${toHexString(sha1(data))}');
  print('md5    ${toHexString(md5(data))}');
  print('crc32  ${crc32(data).toRadixString(16)}');

  final Hasher streaming = sha256Hasher()
    ..add(utf8.encode('hel'))
    ..add(utf8.encode('lo'));
  print('same   ${toHexString(streaming.close())}');

  final Uint8List tag = hmacSha256(utf8.encode('key'), data);
  print('hmac   ${toHexString(tag)}');

  final Uint8List key = pbkdf2HmacSha256(utf8.encode('password'), utf8.encode('salt'), 10000, 32);
  print('pbkdf2 ${toHexString(key)}');

  final Uint8List counter = randomBytes(16);
  final Uint8List sealed = AesCtr(key, counter).process(data);
  final Uint8List opened = AesCtr(key, counter).process(sealed);
  print('aes    ${utf8.decode(opened)}');
}
