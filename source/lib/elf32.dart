// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. 
part of damieng.crypto;

// The ELF32 hasher is used to compute a 32-bit ELF checksum.
class ELF32 implements Hash
{  
  int _hash = 0;
  bool _digestCalled = false;
  
  ELF32();
  ELF32 newInstance() => new ELF32();
  
  void add(List<int> data) {
    if (_digestCalled)
      throw new StateError(_ADD_AFTER_FINALIZE);
    
    data.forEach((f) { 
      _hash = (_hash << 4) + f;
      int work = _hash & 0xF0000000;
      _hash ^= work >> 24;
      _hash &= ~work;
    });
  }

  int get blockSize => 4;

  List<int> close() {
    return _int32ToBigEndianBytes(_hash);
  }    
}