MessageDigest = (function() {
'use strict';
  if(typeof Object.setPrototypeOf !== "function") {
    Object.setPrototypeOf = function(obj, prototype) {
      /*jshint -W103*/
      obj.__proto__ = prototype;
      return obj;
    };
  }

  /**
   * 任意のデータ(メッセージ)をハッシュしたダイジェストを作成します。
   * このオブジェクトは抽象化されたダイジェスト作成機能です。
   * MD5,SHA1などの実際のアルゴリズム指定してインスタンス化するにはcreate()メソッドを使用してください。
   */
  function MessageDigest() {}
  var throwErrorFunc = function() { throw new Error("This function must be overrided, but not."); };
  MessageDigest.prototype._reset = throwErrorFunc;
  MessageDigest.prototype._update = throwErrorFunc;
  MessageDigest.prototype._digest = throwErrorFunc;
  Object.defineProperty(MessageDigest.prototype, "blockSize", { get: throwErrorFunc });
  Object.defineProperty(MessageDigest.prototype, "digestSize", { get: throwErrorFunc });

  MessageDigest.prototype.reset = function() {
    this._reset();
    this.__notUpdated = false;
  };

  /**
   * 現在のメッセージに指定された値を追加します。
   * 引数がArrayもしくはUint8Arrayの場合はその各要素はバイト値(0~255)であるとみなされます。
   * numberの場合は整数値として評価され、4バイトシーケンスであるとみなされます。
   * stringの場合は各文字はUTF-8で符号化されたバイトシーケンスであるとみなされます。
   * @param  {Array.<number>|Uint8Array|number|string} bytesCompatible 追加する値
   * @return {MessageDigest}                 このオブジェクト。
   */
  MessageDigest.prototype.update = function(bytesCompatible) {
    if(typeof bytesCompatible === "string") {
      bytesCompatible = encodeUtf8(bytesCompatible);
    } else if(typeof bytesCompatible === "number") {
      bytesCompatible = bytesCompatible & 0xffffffff;
      bytesCompatible = [
        bytesCompatible & 0xff,
        (bytesCompatible >>> 8) & 0xff,
        (bytesCompatible >>> 16) & 0xff,
        (bytesCompatible >>> 24) & 0xff
      ];
    }
    if(Array.isArray(bytesCompatible)) {
      bytesCompatible = new Uint8Array(bytesCompatible);
    }
    if(!(bytesCompatible instanceof Uint8Array)) throw new TypeError("The argument is incompatible with bytes.");
    this._update(bytesCompatible);
    this.__notUpdated = false;
    return this;
  };

  MessageDigest.prototype.digest = function() {
    if(!this.__notUpdated) {
      this.__chachedDigest = this._digest();
      this.__notUpdated = true;
    }
    return this.__chachedDigest.slice(0);
  };

  /**
   * 現在のメッセージのダイジェストを16進文字列形式で取得します。
   * @param {boolean=} upperCase trueの場合は英字を大文字にした文字列を返します。
   * @return {string} ダイジェスト文字列
   */
  MessageDigest.prototype.digestStr = function(upperCase) {
    var str = "";
    var digest = this.digest();
    digest.forEach(function(byte) {
      var hexStr = byte.toString(16);
      if(hexStr.length < 2) hexStr = "0" + hexStr;
      str += hexStr;
    });
    return upperCase ? str.toUpperCase() : str.toLowerCase();
  };
  Object.defineProperty(MessageDigest, "SHA1", { get: function() { return "SHA1"; } });
  var algorisms = {};
  algorisms[MessageDigest.SHA1] = Sha1;
  MessageDigest.create = function(algorism) {
    var knownAlgorism = algorisms[algorism];
    return knownAlgorism ? new knownAlgorism() : null;
  };

  function encodeUtf8(str) {
    var len = str.length;
    var bytes = [];
    for(var i = 0; i < len; i++) {
      var cp = str.charCodeAt(i);
      if(cp <= 0x7f) {
        bytes.push(cp);
      } else if(cp <= 0x7ff) {
        bytes.push(0xc0 | (cp >>> 6));
        bytes.push(0x80 | (cp & 0x3f));
      } else if(cp <= 0xffff) {
        bytes.push(0xe0 | (cp >>> 12));
        bytes.push(0x80 | ((cp >>> 6) & 0x3f));
        bytes.push(0x80 | (cp & 0x3f));
      } else {
        bytes.push(0xf0 | (cp >>> 18));
        bytes.push(0x80 | ((cp >>> 12) & 0x3f));
        bytes.push(0x80 | ((cp >>> 6) & 0x3f));
        bytes.push(0x80 | (cp & 0x3f));
      }
    }
    return bytes;
  }
  MessageDigest.__encUtf8 = encodeUtf8;

  function pad64(bytes) {
    var blocks = [[]];
    for(var i = 0; i < bytes.length; i++) {
      var blockIdx = Math.floor(i / 64);
      var block = blocks[blockIdx];
      if(!block) {
        block = [];
        blocks.push(block);
      }
      block.push(bytes[i]);
    }
    var lastBlock = blocks[blocks.length - 1];
    lastBlock.push(0x80);
    while(lastBlock.length % 64 != 56) {
      lastBlock.push(0x00);
    }
    var bitLen = [(bytes.length % 536870912) * 8 , ((bytes.length / 536870912) & 0xffffffff) * 8];
    for(var bi = 7; bi >= 0; bi--) {
      lastBlock.push((bitLen[(bi / 4) & 0xf] >>> ((bi % 4) * 8)) & 0xff);
    }
    if(lastBlock.length > 64) {
      blocks.pop();
      blocks.push(lastBlock.slice(0, 64));
      blocks.push(lastBlock.slice(64));
    }
    return blocks;
  }

  function s1(x) {
    return (x << 1) | (x >>> 31);
  }

  function s5(x) {
    return (x << 5) | (x >>> 27);
  }

  function s30(x) {
    return (x << 30) | (x >>> 2);
  }

  function rs(x, n) {
    return (x << n) | (x >>> (32 - n));
  }
  var SHA1_F = new Array(4);
  SHA1_F[0] = function(b, c, d) { return (b & c) | (~b & d); };
  SHA1_F[1] = function(b, c, d) { return b ^ c ^ d; };
  SHA1_F[2] = function(b, c, d) { return (b & c) | (b & d) | (c & d); };
  SHA1_F[3] = SHA1_F[1];
  var SHA1_K = [0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xca62c1d6];
  function Sha1() {
    this.__orgMsg = [];
  }
  //Sha1.MAX_BYTES_LENGTH = 2305843009213693952 - 1; // will be rounded 2305843009213694000.
  Sha1.MAX_BYTES_LENGTH = 9007199254740992; // IEEE 754 safe integer.
  Object.setPrototypeOf(Sha1.prototype, MessageDigest.prototype);
  Object.defineProperty(Sha1.prototype, "blockSize", { get: function() { return 64; }});
  Object.defineProperty(Sha1.prototype, "digestSize", { get: function() { return 20; } });
  Object.defineProperty(Sha1.prototype, "MAX_BYTES_LENGTH", { get: function() { return Sha1.MAX_BYTES_LENGTH; } });
  Sha1.prototype._reset = function() {
    this.__orgMsg = [];
  };
  Sha1.prototype._update = function(bytes) {
    if(Sha1.MAX_BYTES_LENGTH - this.__orgMsg.length < bytes.length) throw new Error("Message length is over the limit.");
    for(var i = 0; i < bytes.length; i++) {
      this.__orgMsg.push(bytes[i]);
    }
  };
  Sha1.prototype._digest = function() {
    var m = pad64(this.__orgMsg);
    var h0 = 0x67452301;
    var h1 = 0xefcdab89;
    var h2 = 0x98badcfe;
    var h3 = 0x10325476;
    var h4 = 0xc3d2e1f0;
    for(var i = 0; i < m.length; i++) {
      var w = [0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];
      for(var j = 0; j < 64; j++) {
        var wi = (j / 4) & 0xf;
        w[wi] = w[wi] | m[i][j] << ((3 - j % 4) * 8);
      }
      var t = 0;
      for(t = 16; t < 80; t++) {
        w.push(s1(w[t-3] ^ w[t-8] ^ w[t-14] ^ w[t-16]));
      }
      var a = h0, b = h1, c = h2, d = h3, e = h4;
      for(t = 0; t < 80; t++) {
        var ci = (t / 20) & 0xff;
        var temp = (s5(a) + SHA1_F[ci](b, c, d) + e + w[t] + SHA1_K[ci]) & 0xffffffff;
        e = d;
        d = c;
        c = s30(b);
        b = a;
        a = temp;
      }
      h0 = (h0 + a) & 0xffffffff;
      h1 = (h1 + b) & 0xffffffff;
      h2 = (h2 + c) & 0xffffffff;
      h3 = (h3 + d) & 0xffffffff;
      h4 = (h4 + e) & 0xffffffff;
    }
    return [
      h0 >>> 24, h0 >>> 16 & 0xff, h0 >>> 8 & 0xff, h0 & 0xff,
      h1 >>> 24, h1 >>> 16 & 0xff, h1 >>> 8 & 0xff, h1 & 0xff,
      h2 >>> 24, h2 >>> 16 & 0xff, h2 >>> 8 & 0xff, h2 & 0xff,
      h3 >>> 24, h3 >>> 16 & 0xff, h3 >>> 8 & 0xff, h3 & 0xff,
      h4 >>> 24, h4 >>> 16 & 0xff, h4 >>> 8 & 0xff, h4 & 0xff,
    ];
  };

  return MessageDigest;
})();

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
Hotp = (function() {
'use strict';
  var MAX_COUNT = 9007199254740992;
  function Hotp() {
    this.counter = 0;
    this.__hmac = new Hmac(MessageDigest.create(MessageDigest.SHA1));
  }
  Hotp.prototype.generate = function(key, digit) {
    if(this.counter > MAX_COUNT) {
      throw new RangeError("This instance has counted max value.");
    }
    if(typeof digit === "undefined") digit = 6;
    return Hotp.generate(key, this.count++, digit, this.__hmac);
  };

  Object.defineProperty(Hotp, "MAX_COUNT", { get: function() { return MAX_COUNT; }});

  /**
   * Generate an HOTP Value.
   * @param  {Array.<number>|Uint8Array} key   key for HMAC-SHA-1
   * @param  {number|Array.<number>|Uint8Array} count C as a number or 8-byte big endian value as 64bit int.
   * @param  {number=} digit result digit(>= 6, default 6).
   * @param  {Hmac=} hmac  specify if need to use other HMAC-HashingAlgorithm. default is HMAC-SHA-1.
   * @return {number}       an HOTP value.
   */
  Hotp.generate = function(key, count, digit, hmac) {
    if(typeof digit !== "number") digit = 6;
    if(digit < 6) throw new RangeError("digit must greater equals 6.");
    if(!hmac) hmac = new Hmac(MessageDigest.create(MessageDigest.SHA1));
    if(typeof count === "number") {
      var lInt = count % 4294967296;
      var hInt = (count / 4294967296) & 0xffffffff;
      count = [
        hInt >>> 24 & 0xff, hInt >>> 16 & 0xff, hInt >>> 8 & 0xff, hInt & 0xff,
        lInt >>> 24 & 0xff, lInt >>> 16 & 0xff, lInt >>> 8 & 0xff, lInt & 0xff,
      ];
    }
    var hs = hmac.h(key, count);
    var sbits = dt(hs);
    var snum = stToNum(sbits);
    return snum % Math.pow(10, digit);
  };

  var CM32 = [
    "A", "B", "C", "D", "E", "F", "G", "H", "I",
    "J", "K", "L", "M", "N", "O", "P", "Q", "R",
    "S", "T", "U", "V", "W", "X", "Y", "Z", "2",
    "3", "4", "5", "6", "7"
  ];
  Hotp.encodeBase32 = function(bytes) {
    var str = "";
    var s = 0;
    var i = 0;
    while(i < bytes.length) {
      s += 5;
      if(s <= 8) {
        str += CM32[(bytes[i] & 0xff) >>> (8 - s) & 0x1f];
        if(s === 8) {
          s = 0;
          ++i;
        }
        continue;
      } else {
        s = s - 8;
        var num = bytes[i] << s & 0x1f;
        if(++i < bytes.length) {
          num += (bytes[i] & 0xff) >>> (8 - s) & 0x0f;
        }
        str += CM32[num];
      }
    }
    while(str.length % 8 !== 0) {
      str += "=";
    }
    return str;
  };

  var NM32 = {
    "A":0, "B":1, "C":2, "D":3, "E":4, "F":5, "G":6, "H":7, "I":8,
    "J":9, "K":10, "L":11, "M":12, "N":13, "O":14, "P":15, "Q":16, "R":17,
    "S":18, "T":19, "U":20, "V":21, "W":22, "X":23, "Y":24, "Z":25, "2":26,
    "3":27, "4":28, "5":29, "6":30, "7":31, "=":0
  };
  var RE_BASE32 = /^[2-7A-Z]+(?:=|={3,4}|={6})?$/;
  Hotp.decodeBase32 = function(str) {
    if(str.length % 8 !== 0) throw new Error("Not base32 encoded string.");
    if(!RE_BASE32.test(str)) throw new Error("Not base32 encoded string.");
    var bytes = [];
    for(var i = 0; i < str.length; i += 8) {
      var n = [];
      for(var j = 0; j < 8; j++) {
        if(str[i + j] in NM32) {
          n.push(NM32[str[i + j]]);
        }
      }
      bytes.push((n[0] << 3) + (n[1] >>> 2));
      bytes.push(((n[1] << 6) + (n[2] << 1) + (n[3] >>> 4)) & 0xff);
      bytes.push(((n[3] << 4) + (n[4] >>> 1)) & 0xff);
      bytes.push(((n[4] << 7) + (n[5] << 2) + (n[6] >>> 3)) & 0xff);
      bytes.push(((n[6] << 5) + n[7]) & 0xff);
    }
    var pn = str.length - str.indexOf("=");
    if(pn === 1) {
      bytes = bytes.slice(0, bytes.length - 1);
    } else if(pn === 3) {
      bytes = bytes.slice(0, bytes.length - 2);
    } else if(pn === 4) {
      bytes = bytes.slice(0, bytes.length - 3);
    } else if(pn === 6) {
      bytes = bytes.slice(0, bytes.length - 4);
    }
    return bytes;
  };

  function dt(hs) {
    var offset = hs[19] & 0xf;
    return [hs[offset + 3], hs[offset + 2], hs[offset + 1], hs[offset] & 0x7f];
  }

  function stToNum(sbits) {
    var num = 0;
    for(var i = 0; i < 4; i++) {
      num += sbits[i] << i * 8;
    }
    return num;
  }

  return Hotp;
})();