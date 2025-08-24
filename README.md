# LinOMR


### Overview:

Oblivious message retrieval (OMR) allows messages resource-limited recipients to outsource the message retrieval process without revealing which messages are pertinent to which recipient.
Its realizations in recent works leave an open problem:
can an OMR scheme be both practical and provably secure against spamming attacks from malicious senders (i.e., DoS-resistant) under standard assumptions?
    


## What's in the demo


## Dependencies

The LinOMR library relies on the following:

- C++ build environment
- CMake build infrastructure
- [SEAL](https://github.com/wyunhao/SEAL) library 4.1 and all its dependencies \
  Notice that we rely on a separate fork of the [original SEAL](https://github.com/microsoft/SEAL) library, which makes some manual change on SEAL interfaces. This fork is used by prior works like [PerfOMR](https://eprint.iacr.org/2024/204), and since our implementation is based on PerfOMR's implementation, we also use this fork of library.
- [PALISADE](https://gitlab.com/palisade/palisade-release) library release v1.11.2 and all its dependencies,\
  as v1.11.2 is not publicly available anymore when this repository is made public, we use v1.11.3 in the instructions instead.
- [NTL](https://libntl.org/) library 11.4.3 and all its dependencies
- [OpenSSL](https://github.com/openssl/openssl) library on branch OpenSSL_1_1_1-stable \
   We use an old version of OpenSSL library for plain AES function without the complex EVP abstraction.
- (Optional) [HEXL](https://github.com/intel/hexl) library 1.2.3 (this would accelerate the SEAL operations with an Intel AVX-512 processor)

### Scripts to install the dependencies and build the binary
Notice that the following instructions are based on installation steps on a Ubuntu 20.04 LTS.
```
# If permission required, please add sudo before the commands as needed

sudo apt-get update && sudo apt-get install build-essential
sudo apt-get install autoconf
sudo apt-get install cmake
sudo apt-get install libgmp3-dev
sudo apt-get install libntl-dev # specify version to be 11.4.3-1build1 if not found
sudo apt install gitc
sudo apt-get install unzip

# With the linomr_code.zip, put it under ~/OMR and unzip it into ObliviousMessageRetrieval dir

 # change build_path to where you want the dependency libraries installed
OMRDIR=~/OMR  
BUILDDIR=$OMRDIR/ObliviousMessageRetrieval/build
BUILDDIR_PIR=$OMRDIR/ObliviousMessageRetrieval/pir/vectorized_batchpir/build

cd $OMRDIR && git clone -b v1.11.9 https://gitlab.com/palisade/palisade-release
cd palisade-release
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=$BUILDDIR -DCMAKE_CXX_COMPILER=g++ -DCMAKE_C_COMPILER=gcc
make
make install

# Old OpenSSL used for plain AES function without EVP abstraction
cd $OMRDIR && git clone -b OpenSSL_1_1_1-stable https://github.com/openssl/openssl
cd openssl
./config --prefix=$BUILDDIR
make
make install

# a separate fork of SEAL library that overwrite some private functions, used in prior works
# we also depend on this library which is used by the prior work we are based on
cd $OMRDIR && git clone https://github.com/wyunhao/SEAL
cd SEAL
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=$BUILDDIR -DSEAL_USE_INTEL_HEXL=ON 
cmake --build build
cmake --install build
# notice that the pir sublib also depends on SEAL, so we also build for it
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=$BUILDDIR_PIR -DSEAL_USE_INTEL_HEXL=ON 
cmake --build build
cmake --install build

# Optional
# Notice that although we 'enable' hexl via command line, it does not take much real effect on GCP instances
# and thus does not have much impact on our runtime
cd $OMRDIR && git clone --branch 1.2.3 https://github.com/intel/hexl
cd hexl
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=$BUILDDIR
cmake --build build
cmake --install build

cd $BUILDDIR
mkdir ../data
mkdir ../data/payloads
mkdir ../data/clues
cmake .. -DCMAKE_PREFIX_PATH=$BUILDDIR
make

cd $BUILDDIR_PIR
cmake -S . -B build -DCMAKE_PREFIX_PATH=./build
cmake --build build
```

### To Run

```
cd $BUILDDIR
./OMRdemos 0 50 65536 612 1
```

### Sample Output for Normal Benchmark
Running the command ```./OMRdemos 0 50 65536 612 1``` would get the following sample output:
```
+------------------------------------+
| Benchmark Test                     |
+------------------------------------+
Preparing database and paramaters...
/
| Encryption parameters :
|   scheme: BFV
|   poly_modulus_degree: 4096
|   coeff_modulus size: 60 (60) bits
|   plain_modulus: 1032193
\
Pertient message indices: [ 265 342 456 475 478 497 820 835 949 958 1078 1098 1196 1291 1317 1370 1467 1469 1552 1553 1587 2087 2369 2385 2439 2540 2582 2626 2699 2952 2970 3025 3080 3145 3183 3315 3358 3375 3385 3419 3451 3516 3585 3586 3628 3725 3799 3828 3906 4067 ]
Database and parameters prepared.

After a*sk... 
After aggregating and transform ntt... 
After subtracting from b... 

Detector running time: 185051 us.

YOU SURE????????? 228
OMR Detector running time: 185279 us.
Decoded pertinent msgs: ---------------
265, 342, 456, 475, 478, 497, 820, 835, 949, 958, 1078, 1098, 1196, 1291, 1317, 1370, 1467, 1469, 1552, 1553, 1587, 2087, 2369, 2385, 2439, 2540, 2582, 2626, 2699, 2952, 2970, 3025, 3080, 3145, 3183, 3315, 3358, 3375, 3385, 3419, 3451, 3516, 3585, 3586, 3628, 3725, 3799, 3828, 3906, 4067, 
Execute PIR: ../pir/vectorized_batchpir/build/bin/vectorized_batch_pir 50 65536 612


Begin PIR server - vectorized_bactchpir ....
BatchPIRServer: Processed database 60 of 60

Public key size: 36980626

Main: All the entries matched!!
PIR recipient time: 4 milliseconds.

PIR Initialization time: 37008 milliseconds
PIR Query generation time: 13 milliseconds
PIR Response generation time: 5736 milliseconds
PIR Total communication: 899 KB

```