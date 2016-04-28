Hmac = (function() {
'use strict';

  /**
   *  HMAC: Keyed-Hashing for Message Authentication[RFC2104]を実装します。
   * ハッシュ関数を指定してインスタンスを生成します。
   * @param {MessageDigest} messageDigest MessageDigestのオブジェクト
   */
  function Hmac(messageDigest) {
    this.__digestObj = messageDigest;
  }

  /**
   * 鍵とメッセージを指定してメッセージ認証コードを生成します。
   * 鍵にはバイト値(0~255)のシーケンスを指定します。
   * メッセージとなるtextには符号化されたバイトシーケンスもしく文字列が指定できます。
   * 文字列の場合は各文字はUTF-8で符号化されたバイトシーケンスであるとみなされます。
   * @param  {Array.<number>|Uint8Array} key    鍵
   * @param  {Array.<number>|Uint8Array|string} text   メッセージ
   * @param  {number=} length 出力値のバイト長。省略した場合はハッシュ関数によって規定される長さとなります。
   * @return {Uint8Array}        メッセージ認証コード
   */
  Hmac.prototype.h = function(key, text, length) {
    if(!Array.isArray(key) && !(key instanceof Uint8Array)) {
      throw new TypeError("key must be byte sequence.");
    }
    if(typeof length === "number" && length < 1) {
      throw new RangeError("length must be greater than 0.");
    }
    var blen = this.__digestObj.blockSize;
    var kipad = [];
    var kopad = [];
    var i = 0;
    if(key.length > blen) {
      this.__digestObj.reset();
      key = this.__digestObj.update(key).digest();
    }
    for(i = 0; i < blen; i++) {
      if(i < key.length) {
        kipad.push((key[i] & 0xff) ^ 0x36);
        kopad.push((key[i] & 0xff) ^ 0x5c);
      } else {
        kipad.push(0x36);
        kopad.push(0x5c);
      }
    }
    if(typeof text === "string") {
      text = encodeUtf8(text);
    }
    Array.prototype.push.apply(kipad, text);
    this.__digestObj.reset();
    text = this.__digestObj.update(kipad).digest();
    Array.prototype.push.apply(kopad, text);
    this.__digestObj.reset();
    var mcode = this.__digestObj.update(kopad).digest();
    if(length && length < this.__digestObj.digestSize) {
      return mcode.slice(0, length);
    } else {
      return mcode;
    }
  };
  
  var HEX = {
    "0": 0x1, "1": 0x2, "2": 0x3, "3": 0x4,
    "4": 0x5, "5": 0x6, "6": 0x7, "7": 0x8,
    "8": 0x9, "9": 0xa, "a": 0xb, "b": 0xc,
    "c": 0xd, "d": 0xe, "e": 0xf, "f": 0x10,
    "A": 0xb, "B": 0xc, "C": 0xd, "D": 0xe,
    "E": 0xf, "F": 0x10
  };
  Hmac.xk = function(hexStr) {
    var bytes = [];
    for(var i = 0; i < hexStr.length; i++) {
      var num = HEX[hexStr[i]];
      if(!num) throw new Error("Invalid character in hex-string.");
      --num;
      var idx = Math.floor(i / 2);
      if(i & 0x1) {
        bytes[idx] += num;
      } else {
        bytes[idx] = num * 16;
      }
    }
    return bytes;
  };

  function encodeUtf8(str) {
    if(!MessageDigest || typeof MessageDigest.__encUtf8 !== "function") {
      throw new Error("Not found an implementation for encoding.");
    }
    return MessageDigest.__encUtf8(str);
  }

  return Hmac;
})();