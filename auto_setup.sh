#!/bin/bash

# Update system 
sudo apt-get update

# Install building tools
sudo apt-get install -y build-essential

# Install python3 
sudo apt-get install -y python3

# Install ZeroMQ
sudo apt-get install -y libzmq3-dev

# Install EMP-Toolkit
# wget https://raw.githubusercontent.com/emp-toolkit/emp-readme/master/scripts/install.py

# python3 install.py --install --tool --ot --agmpc

# Install libgmp libntl libssl, etc.
sudo apt-get install -y autogen automake build-essential cmake git libboost-dev libboost-thread-dev libgmp-dev libntl-dev libsodium-dev libssl-dev libtool m4 texinfo yasm

# Build and install libsecp256k1
git clone https://github.com/bitcoin-core/secp256k1
cd secp256k1
git checkout 423b6d19d373f1224fd671a982584d7e7900bc93
./autogen.sh
./configure
make -j 8
sudo make install

# Build MUSES source code
cd ../MUSES/Server
make clean 
make
cd ../Client
make clean 
make
