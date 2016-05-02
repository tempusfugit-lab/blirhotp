module.exports = {
  options: {
    banner: '<%= longBanner %>'
  },
  dist: {
    src: '<%= concat.dist.dest %>',
    dest: 'dist/<%= pkg.name.replace(/.js$/, "") %>.min.js'
  }
};
