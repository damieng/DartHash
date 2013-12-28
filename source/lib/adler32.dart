// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. 
part of damieng.crypto;

// The Adler hasher is used to compute a 32-bit Adler checksum as
// described at http://en.wikipedia.org/wiki/Adler-32
class Adler32 implements Hash
{  
  static const int _BASE = 65521; // Largest 16-bit prime
  static const int _NMAX = 5552;   
  
  int _hash = 1;
  bool _digestCalled = false;
  
  Adler32();  
  Adler32 newInstance() => new Adler32();
  
  void add(List<int> data) {
    if (_digestCalled)
      throw new StateError(_ADD_AFTER_FINALIZE);

    int a = _hash & _MASK_16;
    int b = (_hash >> 16) & _MASK_16;    
    
    data.forEach((f) { 
      a = (a + f) % _BASE;
      b = (b + a) % _BASE;
    });
    
    _hash = (b << 16) | a; 
  }

  int get blockSize => 4;

  List<int> close() {
    return _int32ToBigEndianBytes(_hash);
  }
}