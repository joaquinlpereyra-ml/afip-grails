const path = require('path');
const webpack = require('webpack');
const CleanWebpackPlugin = require('clean-webpack-plugin');
const CompressionPlugin = require('compression-webpack-plugin');

const BUILD_DIR = path.resolve(__dirname, './src/client/static/build');
const APP_DIR = path.resolve(__dirname, './src/client');

const config = {
   entry: {
     main: APP_DIR + '/index.js'
   },
   output: {
     filename: 'bundle.js',
     path: BUILD_DIR,
   },
   mode: "production",
   module: {
    rules: [
     {
       test: /(\.css|.scss)$/,
       use: [{
           loader: "style-loader" // creates style nodes from JS strings
       }, {
           loader: "css-loader" // translates CSS into CommonJS
       }, {
           loader: "sass-loader" // compiles Sass to CSS
       }]
     },
     {
       test: /\.(jsx|js)?$/,
       use: [{
         loader: "babel-loader",
         options: {
           cacheDirectory: true,
           presets: ['react', 'es2015'] // Transpiles JSX and ES6
         }
       }]
     },
     {
        test: /\.(png|jpg)$/i,
        loader: 'file-loader?name=[path][name].[ext]!extract-loader!html-loader',
      }
    ],
  },
  plugins: [
    new CleanWebpackPlugin(['client/dist']),
    new webpack.ProgressPlugin(),
    new webpack.IgnorePlugin(/^\.\/locale$/, /moment$/),
    new CompressionPlugin({
        test: /\.js(\?.*)?$/i,
        cache: true,
        filename: '[path].gz[query]',
        algorithm: "gzip",
        compressionOptions: { level: 1 },
        threshold: 8192,
        minRatio: 0.8,
        deleteOriginalAssets: false
    })
  ]
};

module.exports = config;