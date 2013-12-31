// Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. 

import 'dart:html';
import 'dart:convert';
import 'package:crypto/crypto.dart';
import '../lib/crypto.dart';

TextAreaElement textInput = querySelector('#textInput');
FileUploadInputElement fileInput = querySelector('#fileInput');

Element output = querySelector('#output');
DivElement results = querySelector('#results');
ParagraphElement message = querySelector('#message');

void main() {
  querySelector("#hashButton").onClick.listen(hashPressed);
}

void hashPressed(MouseEvent event) {
  results.classes.remove('hidden');
  output.children.clear();
    
  if (textInput.value.isNotEmpty) {
    message.text = 'Text "' + textInput.value + '"';
    calculateHashes(new AsciiCodec().encode(textInput.value));
  }

  if (fileInput.files.isNotEmpty) {
    File file = fileInput.files.first;
    message.text = 'File "' + file.name + '", ' + file.size.toString() + ' bytes';
    FileReader reader = new FileReader();
    reader.onLoadEnd.forEach((f) {
      calculateHashes(f.target.result); } );
    reader.readAsArrayBuffer(file);
  }
}

void calculateHashes(List<int> source) {
  var hashers = { 'SHA1'   : new SHA1(),
                  'SHA256' : new SHA256(),
                  'MD2'    : new MD2(),
                  'MD5'    : new MD5(),
                  'CRC8'   : new CRC8(),
                  'CRC16'  : new CRC16(),
                  'CRC32'  : new CRC32(),  
                  'CRC64'  : new CRC64(),
                  'ELF32'  : new ELF32(),
                  'Adler32': new Adler32(),
  };  
  
  hashers.forEach((k, v) {
    v.add(source);
    var row = new TableRowElement();
    row.addCell().text = k;
    var hash = v.close();
    row.addCell().text = CryptoUtils.bytesToHex(hash);
    output.children.add(row);
  });  
}