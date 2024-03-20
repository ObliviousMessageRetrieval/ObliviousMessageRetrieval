# PerfOMR: proof of concept C++ implementation for OMR (Oblivious Message Retrieval) with Reduced Communication and Computation


### Abstract:
Anonymous message delivery systems, such as private messaging services and privacypreserving payment systems, need a mechanism for recipients to retrieve the messages addressed to them, without leaking metadata or letting their messages be linked. Recipients could download all posted messages and scan for those addressed to them, but communication and computation costs are excessive at scale.

We show how untrusted servers can detect messages on behalf of recipients, and summarize these into a compact encrypted digest that recipients can easily decrypt. These servers operate obliviously and do not learn anything about which messages are addressed to which recipients. Privacy, soundness, and completeness hold even if everyone but the recipient is adversarial and colluding (unlike in prior schemes), and are post-quantum secure.

Our starting point is an asymptotically-efficient approach, using Fully Homomorphic Encryption and homomorphically-encoded Sparse Random Linear Codes. We then address the concrete performance using a bespoke tailoring of lattice-based cryptographic components, alongside various algebraic and algorithmic optimizations. This reduces the digest size to a few bits per message scanned. Concretely, the servers’ cost is a couple of USD per million messages scanned, and the resulting digests can be decoded by recipients in under 20ms. However, this initial approach exhibits significant costs in computation per message scanned (109ms), as well as in the size of the associated messages (1kB overhead) and public keys (132kB).

We thus constructs more efficient OMR schemes, by replacing the LWE-based clue encryption of prior works with a Ring-LWE variant, and utilizing the resulting flexibility to improve several components of the scheme.  We thus devise, analyze, and benchmark two protocols:

The first protocol focuses on improving the detector runtime, using a new retrieval circuit that can be homomorphically evaluated more efficiently. Concretely, it takes only ~6.6ms per message scanned, 17x faster than the prior work.

The second protocol focuses on reducing the communication costs, by designing a different homomorphic decryption circuit that allows the parameter of the Ring-LWE encryption to be set such that the public key size is about 200x smaller than the prior work, and the message size is about 1.7x smaller. The runtime of this second construction is ~60ms per message, still ~2x faster than prior works.

Our schemes can thus practically attain the strongest form of receiver privacy for current applications such as privacy-preserving cryptocurrencies.


## License
The OMR library is developed by [Zeyu (Thomas) Liu](https://zeyuthomasliu.github.io/), [Eran Tromer](https://www.tau.ac.il/~tromer/) and [Yunhao Wang](https://wyunhao.github.io/), and is released under the MIT License (see the LICENSE file).


## Model Overview

The following diagram demonstrates the main components of OMR:

![omr](omrHighLevel.png)

Here, we also briefly summarize the high-level scheme notions as below, where more details are provided in Section 3.3 and Section 4 in PerfOMR.
In our system, we have a bulletin board (or board), denoted *BB*, that is publicly available contatining *N* messages. Each message is sent from some sender and is addressed to some recipient(s), whose identities are supposed to remain private.

A message consists of a pair (*xi*, *ci*) where *xi* is the message payload to convey, and *ci* is a clue string which helps notify the intended recipient (and only them) that the message is addressed to them.

To generate the clue, the sender grabs the target recipient's *clue key*.

At any time, any potential recipient *p* may want to retrieve the messages in *BB* that are addressed to them. We call these messages pertinent (to *p*), and the rest are impertinent.

A server, called a detector, helps the recipient *p* detect which message indices in *BB* are pertinent to them, or retrieve the payloads of the pertinent messages. This is done obliviously: even a malicious detector learns nothing about which messages are pertinent. The recipient gives the detector their detection key and a bound *ḱ* on the number of pertinent messages they expect to receive. The detector then accumulates all of the pertinent messages in *BB* into string *M*, called the digest, and sends it to the recipient *p*.

The recipient *p* processes *M* to recover all of the pertinent messages with high probability, assuming a semi-honest detector and that the number of pertinent messages did not exceed *ḱ*.

This code implements PerfOMR schemes (PerfOMR1 in sec 5 and PerfOMR in sec 6) described in the submitted PerfOMR paper, which is based on the OMR described in the [OMR paper](https://eprint.iacr.org/2021/1256.pdf).


## What's in the demo

### Oblivious Message Retrieval
- Obliviously identify the pertinent messages and pack all their contents into a into a single digest.
- Schemes benchmarked: OMR1p (Section 7.4) and OMR2p (Section 7.5) in [OMR](https://eprint.iacr.org/2021/1256.pdf)
- Parameters: N = 2^19 (or *N* = 500,000 padded to 2^19), k = *ḱ* = 50, run on a Google Compute Cloud c2-standard-4instance type (4 hyperthreads of an Intel Xeon 3.10 GHz CPU with 16GB RAM)
- Measurement: 
  - <img src="omr_measurement.png" alt="omr_measurement" width="400"/>



### PerfOMR: OMR with Reduced Communication and Computation
- Obliviously identify the pertinent messages and pack all their contents into a into a single digest.
- Schemes benchmarked (in PerfOMR): 
    - main scheme PerfOMR1 (Section 5.3)
    - alternative scheme PerfOMR2 (Section 6)
- Parameters: N = 2^19, 2^20, 2^21, k = *ḱ* = 50, 100, 150, run on a a Google Compute Cloud c2-standard-4instance type (4 hyperthreads of an Intel Xeon 3.10 GHz CPU with 16GB RAM)
- Measurement (with parameters in Section 7):
    - <img src="perfomr_measurement.png" alt="perfomr_measurement" width="800"/>
    - Detector run time scaling:
        - runtime vs. *ḱ* <img src="perfomr_runtime_k.png" alt="perfomr_runtime_k" width="700"/>
        - runtime vs. *N* <img src="perfomr_runtime_N.png" alt="perfomr_runtime_N" width="700"/>


### Parameters Summary
- OMR: N = 2^19 (or *N* = 500,000 padded to 2^19), k = *ḱ* = 50. Benchmark results on a Google Compute Cloud c2-standard-4instance type (4 hyperthreads of an Intel Xeon 3.10 GHz CPU with 16GB RAM) are reported in Section 10 in [OMR paper](https://eprint.iacr.org/2021/1256.pdf).

- PerfOMR: N = 2^19, 2^20, 2^21, k = *ḱ* = 50, 100, 150. Benchmark results on a Google Compute Cloud c2-standard-4instance type (4 hyperthreads of an Intel Xeon 3.10 GHz CPU with 16GB RAM) are reported in Section 7 in the submitted [PerfOMR paper](https://eprint.iacr.org/2024/204.pdf).



## Dependencies

The OMR library relies on the following:

- C++ build environment
- CMake build infrastructure
- [SEAL](https://github.com/microsoft/SEAL) library 4.1 and all its dependencies \
  Notice that we made some manual change on SEAL interfaces to facilitate our implementation and thus a built-in dependency of SEAL is directly included under 'build' directory.
- [PALISADE](https://gitlab.com/palisade/palisade-release) library release v1.11.2 and all its dependencies,\
  as v1.11.2 is not publicly available anymore when this repository is made public, we use v1.11.3 in the instructions instead.
- [NTL](https://libntl.org/) library 11.4.3 and all its dependencies
- [OpenSSL](https://github.com/openssl/openssl) library on branch OpenSSL_1_1_1-stable \
   We use an old version of OpenSSL library for plain AES function without the complex EVP abstraction.
- (Optional) [HEXL](https://github.com/intel/hexl) library 1.2.3

### Scripts to install the dependencies and build the binary
Notice that the following instructions are based on installation steps on a Ubuntu 20.04 LTS.
```
# If permission required, please add sudo before the commands as needed

sudo apt-get update && sudo apt-get install build-essential # if needed
sudo apt-get install autoconf # if no autoconf
sudo apt-get install cmake # if no cmake
sudo apt-get install libgmp3-dev # if no gmp
sudo apt-get install libntl-dev=11.4.3-1build1 # if no ntl
sudo apt-get install unzip # if no unzip

# If you have the PERFOMR_code.zip directly, put it under ~/OMR and unzip it into ObliviousMessageRetrieval dir, otherwise:
mkdir -p ~/OMR
cd ~/OMR
wget https://github.com/ObliviousMessageRetrieval/ObliviousMessageRetrieval/raw/usenix_artifact/PERFOMR_code.zip
unzip PERFOMR_code.zip

OMRDIR=~/OMR   # change build_path to where you want the dependency libraries installed
BUILDDIR=$OMRDIR/ObliviousMessageRetrieval/build

cd $OMRDIR && git clone -b v1.11.3 https://gitlab.com/palisade/palisade-release
cd palisade-release
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=$BUILDDIR
make
make install

# Old OpenSSL used for plain AES function without EVP abstraction
cd $OMRDIR && git clone -b OpenSSL_1_1_1-stable https://github.com/openssl/openssl
cd openssl
./config --prefix=$BUILDDIR
make
make install

# Optional
# Notice that although we 'enable' hexl via command line, it does not take much real effect on GCP instances
# and thus does not have much impact on our runtime
cd $OMRDIR && git clone --branch 1.2.3 https://github.com/intel/hexl
cd hexl
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=$BUILDDIR
cmake --build build
cmake --install build

cd $OMRDIR/ObliviousMessageRetrieval/build
mkdir ../data
mkdir ../data/payloads
mkdir ../data/clues
mkdir ../data/cluePoly
mkdir ../data/processedCM
cmake .. -DCMAKE_PREFIX_PATH=$BUILDDIR
make
```

### To Run

```
cd $BUILDDIR
# to run our main PerfOMR construction: for example: ./OMRdemos perfomr1 1 2 32768 50
./OMRdemos <perfomr1/perfomr2> <number_of_cores> <number_of_messages_in_bundle> <number_of_bundles> <number_of_pert_msgs>

```

### To Reproduce the Main Benchmark Result
- With fixed *ḱ* i.e., the number of pertinent messages), and demonstrate the runtime scaling with *N* (i.e., the number of transactions)
```
./OMRdemos perfomr1 1 8 65536 50 
./OMRdemos perfomr1 1 8 131072 50
./OMRdemos perfomr1 1 8 262144 50
./OMRdemos perfomr2 1 8 65536 50
./OMRdemos perfomr2 1 8 131072 50
./OMRdemos perfomr2 1 8 262144 50
```
- With fixed *N*, and demonstrate the runtime scaling with *ḱ*:
```
./OMRdemos perfomr1 1 8 65536 50
./OMRdemos perfomr1 1 8 65536 100
./OMRdemos perfomr1 1 8 65536 150
./OMRdemos perfomr2 1 8 65536 50
./OMRdemos perfomr2 1 8 65536 100
./OMRdemos perfomr2 1 8 65536 150
```
- To demonstrate the runtime under multicore (2 cores):
```
./OMRdemos perfomr1 2 8 65536 50
./OMRdemos perfomr2 2 8 65536 50
```

### Sample Output
```
Preparing database and paramaters...
Pertient message indices: [ 3558 3683 3881 4099 4857 5142 5241 7165 7774 7806 8085 8375 8381 8597 8608 8769 9119 9960 10478 10689 10928 12291 12937 13238 15021 16730 16929 19011 19745 20384 21812 22398 22565 23523 23913 24844 24929 25352 25687 26401 27076 27309 27372 28726 30793 31006 31344 31838 32077 32215 ]
/
| Encryption parameters :
|   scheme: BFV
|   poly_modulus_degree: 32768
|   coeff_modulus size: 905 (35 + 60 + 60 + 60 + 60 + 60 + 60 + 60 + 60 + 60 + 60 + 60 + 60 + 60 + 30 + 60) bits
|   plain_modulus: 65537
\
Database and parameters prepared.

Preprocess switching key time: 264900272 us.
ClueToPackedPV time: 160386979 us.
PVUnpack time: 675661388 us.
ExpandedPVToDigest time: 218222953 us.

Detector running time: 965717410 us.
Digest size: 568138 bytes

Recipient running time: 25684 us.
Result is correct!
```
