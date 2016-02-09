This is an attempt to convert h2o from C to C++, right now it still uses the ".c" extension to make it easy to compare with the original h2o files, it's started with h2o version 1.7, it's passing all tests that my machine can perform, to compile it's the same as the original h2o except that it uses a C++ compiler instead of C, right now it doesn't include any C++ library.

H2O - an optimized HTTP server with support for HTTP/1.x and HTTP/2
===

[![Build Status](https://travis-ci.org/h2o/h2o.svg?branch=master)](https://travis-ci.org/h2o/h2o)

Copyright (c) 2014-2016 [DeNA Co., Ltd.](http://dena.com/), [Kazuho Oku](https://github.com/kazuho/), [Tatsuhiko Kubo](https://github.com/cubicdaiya/), [Domingo Alvarez Duarte](https://github.com/mingodad/), [Nick Desaulniers](https://github.com/nickdesaulniers/), [Marc Hörsken](https://github.com/mback2k), [Masahiro Nagano](https://github.com/kazeburo/), Jeff Marrison, [Daisuke Maki](https://github.com/lestrrat/), [Laurentiu Nicola](https://github.com/GrayShade/), [Justin Zhu](https://github.com/zlm2012/), [Tatsuhiro Tsujikawa](https://github.com/tatsuhiro-t), [Ryosuke Matsumoto](https://github.com/matsumoto-r), [Masaki TAGAWA](https://github.com/mochipon), [Masayoshi Takahashi](https://github.com/takahashim), [Chul-Woong Yang](https://github.com/cwyang), [Shota Fukumori](https://github.com/sorah)

H2O is a new generation HTTP server.
Not only is it very fast, it also provides much quicker response to end-users when compared to older generations of HTTP servers.

Written in C and licensed under [the MIT License](http://opensource.org/licenses/MIT), it can also be used as a library.

For more information, please refer to the documentation at [h2o.examp1e.net](https://h2o.examp1e.net).
