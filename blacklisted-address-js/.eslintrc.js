module.exports = {
  env: {
    commonjs: true,
    es2021: true,
    jest: true,
    node: true,
  },
  extends: [
    'airbnb-base',
  ],
  parserOptions: {
    ecmaVersion: 12,
    sourceType: 'module',
  },
  rules: {
  },
  overrides: [
    {
      files: '*',
      rules: {
        'no-plusplus': 'off',
      },
    },
  ],
};
