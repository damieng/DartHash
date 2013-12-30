// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. 
part of damieng.crypto;

// The CRC64 hasher is used to compute a 64-bit CRC as described at
// http://en.wikipedia.org/wiki/Cyclic_redundancy_check
class CRC64 implements Hash
{
  static const int DefaultPolynomial = 0xD800000000000000; // Reversed ISO
  
  int _hash, _seed, _polynomial;
  List<int> _finalHash, _table, _defaultTable;
  
  CRC64({int polynomial: DefaultPolynomial, int seed: 0 }) {
    _hash = _seed = seed;
    _table = _createTable(_polynomial = polynomial);
  }  
  
  CRC64 newInstance() => new CRC64(polynomial: _polynomial, seed:_seed);
  
  void add(List<int> data) {
    if (_finalHash != null)
      throw new StateError(_ADD_AFTER_FINALIZE);

    data.forEach((f) => _hash = (_hash >> 8) ^ _table[(f ^ _hash) & _MASK_8]);    
  }

  int get blockSize => 8;

  List<int> close() {
    if (_finalHash == null)
      _finalize();

    return _finalHash;
  }
  
  _finalize() {
    _finalHash = _int64ToBigEndianBytes(_hash);
  }
  
  _createTable(int polynomial) {
    if (polynomial == DefaultPolynomial && _defaultTable != null)
      return _defaultTable;
    
    List<int> newTable = new List<int>(256);
    
    for (var i = 0; i < newTable.length; ++i) {
      var entry = i;
      for (var j = 0; j < 8; ++j)
        if ((entry & 1) == 1)
          entry = (entry >> 1) ^ polynomial;
        else
          entry = entry >> 1;
        newTable[i] = entry;
    }    
    
    if (polynomial == DefaultPolynomial)
      _defaultTable = newTable;
    
    return newTable;
  }
}