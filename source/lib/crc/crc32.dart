// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. 
part of damieng.crypto;

// The CRC32 hasher is used to compute a 32-bit CRC as described at
// http://en.wikipedia.org/wiki/Cyclic_redundancy_check
class CRC32 implements Hash
{
  static const int DefaultPolynomial = 0xEDB88320; // Reversed format
  static const int DefaultSeed = 0xFFFFFFFF;       // We don't invert seed
  static List<int> _defaultTable;
  
  int _hash, _seed, _polynomial;
  List<int> _finalHash, _table;
  
  CRC32({int polynomial : DefaultPolynomial, int seed: DefaultSeed }) {
    _hash = _seed = seed;
    _table = _createTable(_polynomial = polynomial);
  }
  
  CRC32 newInstance() =>  new CRC32(polynomial: _polynomial, seed: _seed);
  
  void add(List<int> data) {
    if (_finalHash != null)
      throw new StateError(_ADD_AFTER_FINALIZE);

    data.forEach((f) => _hash = ((_hash >> 8) ^ _table[(f ^ _hash) & _MASK_8]) & _MASK_32);
  }

  int get blockSize => 4;

  List<int> close() {
    if (_finalHash == null)
      _finalize();

    return _finalHash;
  }
  
  _finalize() {
    _finalHash = _int32ToBigEndianBytes(~_hash);
  }
  
  _createTable(int polynomial) {
    if (polynomial == DefaultPolynomial && _defaultTable != null)
      return _defaultTable;
    
    List<int> newTable = new List<int>(256);
    
    for (var i = 0; i < newTable.length; i++) {
      var entry = i;
      for (var j = 0; j < 8; j++)
        if ((entry & 1) == 1)
          entry = (entry >> 1) ^ polynomial;
        else
          entry = entry >> 1;
        entry &= _MASK_32;
        newTable[i] = entry;
    }    
    
    if (polynomial == DefaultPolynomial)
      _defaultTable = newTable;
    
    return newTable;
  }
}