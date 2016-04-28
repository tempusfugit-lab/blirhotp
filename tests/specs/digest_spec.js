(function() {
describe("MeesageDigest", function() {
  describe("SHA1", function() {
    var digestObj = MessageDigest.create(MessageDigest.SHA1);
    beforeEach(function() {
        digestObj.reset();
      });
    it("TEST1", function() {
      var msg = "abc";
      var digest = "A9993E364706816ABA3E25717850C26C9CD0D89D";
      expect(digestObj.update(msg).digestStr(true)).toBe(digest);
    });
    it("TEST2", function() {
      var msg = "abcdbcdecdefdefgefghfghighijhi" +
                "jkijkljklmklmnlmnomnopnopq";
      var digest = "84983E441C3BD26EBAAE4AA1F95129E5E54670F1";
      expect(digestObj.update(msg).digestStr(true)).toBe(digest);
    });
    it("TEST3", function() {
      var msg = "a";
      var digest = "34AA973CD4C4DAA4F61EEB2BDBAD27316534016F";
      for(var i = 0; i < 1000000; i++) {
        digestObj.update(msg);
      }
      expect(digestObj.digestStr(true)).toBe(digest);
    });
    it("TEST4", function() {
      var msg = "01234567012345670123456701234567" +
                "01234567012345670123456701234567";
      var digest = "DEA356A2CDDD90C7A7ECEDC5EBB563934F460452";
      for(var i = 0; i < 10; i++) {
        digestObj.update(msg);
      }
      expect(digestObj.digestStr(true)).toBe(digest);
    });
  });
});
})();