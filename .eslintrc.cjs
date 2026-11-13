module.exports = {
  root: true,
  extends: ['standard'],
  env: {
    browser: true,
    es2022: true,
    node: true
  },
  parserOptions: {
    ecmaVersion: 2022,
    sourceType: 'module'
  },
  ignorePatterns: [
    'coverage/',
    'dist/',
    'node_modules/',
    'src/plugins.generated.js',
    'src/vendor/',
    'vendor/'
  ],
  overrides: [{
    files: ['scripts/vendor-node-shims/*.mjs'],
    // These namespace exports include legacy APIs without calling them.
    rules: { 'n/no-deprecated-api': 'off' }
  }],
  rules: {
    'no-unused-vars': ['error', { argsIgnorePattern: '^_' }]
  }
}
