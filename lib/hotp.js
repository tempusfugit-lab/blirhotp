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
  Hotp.decodeBase32 = function(str) {
    if(str.length % 8 !== 0) throw new Error("Not base32 encoded string.");
    if(!/^[2-7A-Z]+(?:=|={3,4}|={6})?$/.test(str)) throw new Error("Not base32 encoded string.");
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