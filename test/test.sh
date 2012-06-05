#!/bin/bash

sudo apt-get update

sudo apt-get install -y git build-essential libpam-dev

git clone git://github.com/portertech/ruby-pam.git
cd ruby-pam

ruby extconf.rb
make
sudo make install
