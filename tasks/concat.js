module.exports = {
  dist: {
    src: ["lib/digest.js", "lib/hmac.js", "lib/hotp.js"],
    dest: "dist/<%= pkg.name %>-<%= pkg.version %>.js",
  }
};
