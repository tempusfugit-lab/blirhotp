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
      bytesCompatible = Uint8Array.from(bytesCompatible);
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
