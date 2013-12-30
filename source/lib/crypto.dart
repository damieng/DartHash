library damieng.crypto;

import 'package:crypto/crypto.dart';

part 'adler32.dart';
part 'crc/crc8.dart';
part 'crc/crc16.dart';
part 'crc/crc32.dart';
part 'crc/crc64.dart';
part 'elf32.dart';

const _MASK_8 = 0xff;
const _MASK_16 = 0xffff;
const _MASK_32 = 0xffffffff;
const _ADD_AFTER_FINALIZE = 'Hash update method called after digest was retrieved';

// Convert a 16-bit integer to 2 big endian bytes
_int16ToBigEndianBytes(int value) {
  List<int> bytes = new List(2);
  bytes[0] = (value >> 8) & _MASK_8;
  bytes[1] = (value >> 0) & _MASK_8;
  return bytes;
}

// Convert a 32-bit integer to 4 big endian bytes
_int32ToBigEndianBytes(int value) {
  List<int> bytes = new List(4);
  bytes[0] = (value >> 24) & _MASK_8;
  bytes[1] = (value >> 16) & _MASK_8;
  bytes[2] = (value >> 8) & _MASK_8;
  bytes[3] = (value >> 0) & _MASK_8;
  return bytes;
}

// Convert a 64-bit integer to 8 big endian bytes
_int64ToBigEndianBytes(int value) {
  List<int> bytes = new List(8);
  bytes[0] = (value >> 56) & _MASK_8;
  bytes[1] = (value >> 48) & _MASK_8;
  bytes[2] = (value >> 40) & _MASK_8;
  bytes[3] = (value >> 32) & _MASK_8;
  bytes[4] = (value >> 24) & _MASK_8;
  bytes[5] = (value >> 16) & _MASK_8;
  bytes[6] = (value >> 8) & _MASK_8;
  bytes[7] = (value >> 0) & _MASK_8;
  return bytes;
}