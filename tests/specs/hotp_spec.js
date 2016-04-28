(function() {
describe("Hotp", function() {
  var secret = Hmac.xk("3132333435363738393031323334353637383930");
  it("0", function() {
    expect(Hotp.generate(secret, 0)).toBe(755224);
  });
  it("1", function() {
    expect(Hotp.generate(secret, 1)).toBe(287082);
  });
  it("2", function() {
    expect(Hotp.generate(secret, 2)).toBe(359152);
  });
  it("3", function() {
    expect(Hotp.generate(secret, 3)).toBe(969429);
  });
  it("4", function() {
    expect(Hotp.generate(secret, 4)).toBe(338314);
  });
  it("5", function() {
    expect(Hotp.generate(secret, 5)).toBe(254676);
  });
  it("6", function() {
    expect(Hotp.generate(secret, 6)).toBe(287922);
  });
  it("7", function() {
    expect(Hotp.generate(secret, 7)).toBe(162583);
  });
  it("8", function() {
    expect(Hotp.generate(secret, 8)).toBe(399871);
  });
  it("9", function() {
    expect(Hotp.generate(secret, 9)).toBe(520489);
  });
});
})();