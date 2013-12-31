// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. 
part of damieng.crypto;

// The MD2 hasher is used to compute a 16 byte MD2.
class MD2 implements Hash
{
  static const List<int> _table = const [
     41,  46,  67, 201, 162, 216, 124,   1,
     61,  54,  84, 161, 236, 240,   6,  19,
     98, 167,   5, 243, 192, 199, 115, 140,
     152, 147,  43, 217, 188,  76, 130, 202,
     30, 155,  87,  60, 253, 212, 224,  22,
     103,  66, 111,  24, 138,  23, 229,  18,
     190,  78, 196, 214, 218, 158, 222,  73,
     160, 251, 245, 142, 187,  47, 238, 122,
     169, 104, 121, 145,  21, 178,   7,  63,
     148, 194,  16, 137,  11,  34,  95,  33,
     128, 127,  93, 154,  90, 144,  50,  39,
     53,  62, 204, 231, 191, 247, 151,   3,
     255,  25,  48, 179,  72, 165, 181, 209,
     215,  94, 146,  42, 172,  86, 170, 198,
     79, 184,  56, 210, 150, 164, 125, 182,
     118, 252, 107, 226, 156, 116,   4, 241,
     69, 157, 112,  89, 100, 113, 135,  32,
     134,  91, 207, 101, 230,  45, 168,   2,
     27,  96,  37, 173, 174, 176, 185, 246,
     28,  70,  97, 105,  52,  64, 126,  15,
     85,  71, 163,  35, 221,  81, 175,  58,
     195,  92, 249, 206, 186, 197, 234,  38,
     44,  83,  13, 110, 133,  40, 132,   9,
     211, 223, 205, 244,  65, 129,  77,  82,
     106, 220,  55, 200, 108, 193, 171, 250,
     36, 225, 123,   8,  12, 189, 177,  74,
     120, 136, 149, 139, 227,  99, 232, 109,
     233, 203, 213, 254,  59,   0,  29,  57,
     242, 239, 183,  14, 102,  88, 208, 228,
     166, 119, 114, 248, 235, 117,  75,  10,
     49,  68,  80, 180, 143, 237,  31,  26,
     219, 153, 141,  51, 159,  17, 131,  20
  ]; 
    
  List<int> _pendingData = [];
  final List<int> _x = new List<int>(48);
  final List<int> _c = new List<int>(_chunkSize);
  int _l = 0;
  bool _digestCalled = false;
  static const int _chunkSize = 16;
  
  MD2() {
    _x.fillRange(0, _x.length, 0);
    _c.fillRange(0, _c.length, 0);
  }
  
  MD2 newInstance() => new MD2();
  
  void add(List<int> data) {
    if (_digestCalled)
      throw new StateError(_ADD_AFTER_FINALIZE);

    _pendingData.addAll(data);
    _iterate();
  }

  List<int> close() {
    if (_digestCalled) {
      return _resultAsBytes();
    }

    _digestCalled = true;
    _finalizeData();
    _iterate();
    assert(_pendingData.length == 0);
    return _resultAsBytes();
  }
  
  List<int> _resultAsBytes() {
    var result = [];
    result.addAll(_x.take(_chunkSize));
    return result;
  }
  
  int get blockSize => 16;

  void _iterate() {
    while (_pendingData.length >= _chunkSize) {
      _updateHash(_pendingData.take(_chunkSize));
      _pendingData = _pendingData.sublist(_chunkSize);
    }
  }
  
  void _finalizeData() { 
    int pending = _pendingData.length % _chunkSize;
    int pad = _chunkSize - pending;
    for (int i = 0; i < pad; i ++)
      _pendingData.add(pad);
    _iterate();
    
    _updateHash(_c.take(_chunkSize));
  }
    
  void _updateHash(Iterable<int> m) {
    assert(m.length == _chunkSize);

    int tL = _l;
    int i = 0;
    for(var b in m)
    {
      int u = b & _MASK_8;
      _x[16 + i] = u;
      _x[32 + i] = _x[i] ^ u;
      tL = (_c[i] ^= _table[u ^ tL]);
      i++;
    }
    _l = tL;

    int t = 0;
    for (int j = 0; j < 18; j ++) {
      for (int k = 0; k < 48; k += 8) {
        t = (_x[k + 0] ^= _table[t]);
        t = (_x[k + 1] ^= _table[t]);
        t = (_x[k + 2] ^= _table[t]);
        t = (_x[k + 3] ^= _table[t]);
        t = (_x[k + 4] ^= _table[t]);
        t = (_x[k + 5] ^= _table[t]);
        t = (_x[k + 6] ^= _table[t]);
        t = (_x[k + 7] ^= _table[t]);
      }
      t = (t + j) & _MASK_8;
    }
  }  
}