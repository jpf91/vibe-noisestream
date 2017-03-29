#!/bin/bash

git clone git://github.com/jedisct1/libsodium.git
pushd libsodium
    git checkout 1.0.12
    ./autogen.sh
    ./configure --prefix=/usr
    make
    sudo make install
popd

git clone https://github.com/rweather/noise-c.git
pushd noise-c
    ./autogen.sh
    ./configure --with-libsodium --prefix=/usr
    pushd src
    make
    sudo make install
    popd
popd

dub test -b unittest-cov --combined
chmod +x ./doveralls
./doveralls
