#!/bin/bash
make defconfig-hwsim
sudo make -j 6
sudo make install
./../../../Thesis/VM/Scripts/init.sh

