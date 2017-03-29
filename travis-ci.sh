#!/bin/bash

mkdir libraries
INSTALLPATH=${PWD}/libraries

export LIBRARY_PATH=${INSTALLPATH}/lib

git clone git://github.com/jedisct1/libsodium.git
pushd libsodium
    git checkout 1.0.12
    ./autogen.sh
    ./configure --prefix=/
    make
    DESTDIR=${INSTALLPATH} make install
popd

git clone https://github.com/rweather/noise-c.git
pushd noise-c
    ./autogen.sh
    ./configure --with-libsodium --prefix=/
    make
    DESTDIR=${INSTALLPATH} make install
popd

dub test -b unittest-cov --combined
./doveralls
