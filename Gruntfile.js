/*global module:false*/
module.exports = function (grunt) {
  'use strict';

  require('time-grunt')(grunt);

  var licenseText = grunt.file.read("LICENSE", {encoding: "utf8"}).toString("utf8");
  licenseText = "/*\n" + licenseText.replace(/^/mg, " * ") + "\n */\n";

  var config = {
    // Metadata.
    pkg: grunt.file.readJSON('package.json'),
    shortBanner: '/*! <%= pkg.name %> - v<%= pkg.version %>\n' +
      ' *  Release on: <%= grunt.template.today("yyyy-mm-dd") %>\n' +
      '<%= pkg.homepage ? " *  " + pkg.homepage + "\\n" : "" %>' +
      ' *  Copyright (c) <%= grunt.template.today("yyyy") %> <%= pkg.author.name %>\n' +
      ' *  Licensed <%= pkg.license %> */\n',
    longBanner: licenseText,
  };

  var path = require('path');

  require('load-grunt-config')(grunt, {
    init: true,
    configPath: path.join(process.cwd(), 'tasks'),
    config: config,
    jitGrunt: {
      changelog: 'grunt-conventional-changelog'
    }
  });
};
