module.exports = {
  lib: {
    template: 'umd',
    indent: '  ',
    src: 'lib/<%= pkg.name.replace(/.js$/, "") %>.js',
    dest: 'dist/<%= pkg.name.replace(/.js$/, "") %>.js',
    returnExportsGlobal: 'blirhotp',
    deps: {
      default: [],
      amd: [],
      cjs: [],
      global: []
    }
  }
};
