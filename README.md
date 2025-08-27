# LinOMR


### Abstract:

Anonymous message delivery, as in privacy-preserving blockchain and private messaging applications, needs to protect recipient metadata: eavesdroppers should not be able to link messages to their recipients. This raises the question: how can untrusted servers assist in delivering the pertinent messages to each recipient, without learning which messages are addressed to whom?

Recent work constructed Oblivious Message Retrieval (OMR) protocols that outsource the message detection and retrieval in a privacy-preserving way, using homomorphic encryption. Their construction exhibits significant costs in computation per message scanned (～0.1 second), as well as in the size of the associated messages (～1 kB overhead) and public keys (～132 kB).

This work constructs more efficient OMR schemes, by replacing the LWE-based clue encryption of prior works with a Ring-LWE variant, and utilizing the resulting flexibility to improve several components of the scheme. We thus devise, analyze, and benchmark two protocols:

The first protocol focuses on improving the detector runtime, using a new retrieval circuit that can be homomorphically evaluated $15$x faster than the prior work.
  
The second protocol focuses on reducing the communication costs, by designing a different homomorphic decryption circuit that allows the parameter of the Ring-LWE encryption to be set such that the public key size is about 235x smaller than the prior work, and the message size is roughly 1.6x smaller. The runtime of this second construction is ～40.0 ms per message, still more than 2.5x faster than prior works.
    

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
BUILDDIR_PIR=$OMRDIR/ObliviousMessageRetrieval/pir/vectorized_batchpir

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
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=$BUILDDIR_PIR/build -DSEAL_USE_INTEL_HEXL=ON 
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
cmake -S . -B build -DCMAKE_PREFIX_PATH=$BUILDDIR_PIR/build
cmake --build build
```

### To Run

```
cd $BUILDDIR
# ./OMRdemos <is_param1> <number_of_pertinent_msg> <db_size> <payload_size>
./OMRdemos 1 50 65536 612
```

### Sample Output for Normal Benchmark
Running the command ```./OMRdemos 1 50 65536 612``` would get the following sample output:
```
+------------------------------------+
| Benchmark Test                     |
+------------------------------------+
Preparing database and paramaters...
/
| Encryption parameters :
|   scheme: BFV
|   poly_modulus_degree: 2048
|   coeff_modulus size: 60 (60) bits
|   plain_modulus: 4169729
\
Pertient message indices: [ 197 246 262 323 425 487 500 555 561 564 581 589 657 667 679 744 783 821 871 970 981 1014 1021 1041 1050 1060 1100 1115 1132 1236 1254 1341 1342 1366 1411 1436 1546 1575 1596 1599 1674 1687 1743 1825 1828 1842 1855 1951 1981 2012 ]
Database and parameters prepared.

Execute OMR... 
OMR Detector running time: 1151242 us.

Execute PIR with command: ../pir/vectorized_batchpir/build/bin/vectorized_batch_pir 50 65536 612


Begin PIR server - vectorized_bactchpir ....
BatchPIRServer: Processed database 60 of 60

Public key size: 36980074

Main: All the entries matched!!
PIR recipient time: 4 milliseconds.

PIR Initialization time: 37268 milliseconds
PIR Query generation time: 13 milliseconds
PIR Response generation time: 5869 milliseconds
PIR Total communication: 899 KB
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

### To reproduce Table 2:
```
# For param1:
./OMRdemos 1 50 524288 612
# For param2:
./OMRdemos 0 50 524288 612
```

### To reproduce Figure 2-6:
```
# For param1 or param2, N = {2^16, 2^17, 2^18, 2^19, 2^20, 2^21, 2^22, 2^23}
./OMRdemos <1/0> 500 <N> 612

# For param1 or param2, k = {125, 250, 500, 1000, 2000, 4000, 8000, 16000}
./OMRdemos <1/0> <k> 2097152 612

# For param1 or param2, P = {612, 1224, 1836, 2448, 3060}
./OMRdemos <1/0> 500 2097152 <P>

```