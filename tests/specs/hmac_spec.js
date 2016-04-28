(function() {
describe("Hmac", function() {
  describe("HMAC-SHA-1", function() {
    var hmac = new Hmac(MessageDigest.create(MessageDigest.SHA1));
    it("1", function() {
      var key = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
      var data = "Hi There";
      var digest = "b617318655057264e28bc0b6fb378c8ef146be00";
      expect(bth(hmac.h(Hmac.xk(key), data))).toBe(digest);
    });
    it("2", function() {
      var key = "4a656665"; // "Jefe"
      var data = "what do ya want for nothing?";
      var digest = "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79";
      expect(bth(hmac.h(Hmac.xk(key), data))).toBe(digest);
    });
    it("3", function() {
      var key = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
      var data = [];
      for(var i = 0; i < 50; i++) {
        data.push(0xdd);
      }
      var digest = "125d7342b9ac11cd91a39af48aa17b4f63f175d3";
      expect(bth(hmac.h(Hmac.xk(key), data))).toBe(digest);
    });
    it("4", function() {
      var key = "0102030405060708090a0b0c0d0e0f10111213141516171819";
      var data = [];
      for(var i = 0; i < 50; i++) {
        data.push(0xcd);
      }
      data = new Uint8Array(data);
      var digest = "4c9007f4026250c6bc8414f9bf50c86c2d7235da";
      expect(bth(hmac.h(Hmac.xk(key), data))).toBe(digest);
    });
    it("5", function() {
      var key = "0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c0c";
      var data = "Test With Truncation";
      var digest = "4c1a03424b55e07fe7f27be1";
      var length = 12;
      expect(bth(hmac.h(Hmac.xk(key), data, length))).toBe(digest);
    });
    it("6", function() {
      var key = "";
      for(var i = 0; i < 80; i++) {
        key += "aa";
      }
      var data = "Test Using Larger Than Block-Size Key - Hash Key First";
      var digest = "aa4ae5e15272d00e95705637ce8a3b55ed402112";
      expect(bth(hmac.h(Hmac.xk(key), data))).toBe(digest);
    });
    it("7", function() {
      var key = "";
      for(var i = 0; i < 80; i++) {
        key += "aa";
      }
      var data = "Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data";
      var digest = "e8e99d0f45237d786d6bbaa7965c7808bbff1a91";
      expect(bth(hmac.h(Hmac.xk(key), data))).toBe(digest);
    });
  });
});

function bth(bytes) {
  var str = "";
  bytes.forEach(function(byte) {
    var hexStr = byte.toString(16);
    if(hexStr.length < 2) hexStr = "0" + hexStr;
    str += hexStr;
  });
  return str;
}

})();