# Group Oblivious Message Retrieval: proof of concept C++ implementation for GOMR


### Abstract:
Anonymous message delivery systems, such as private messaging services and privacypreserving payment systems, need a mechanism for recipients to retrieve the messages addressed to them, without leaking metadata or letting their messages be linked. Recipients could download all posted messages and scan for those addressed to them, but communication and computation costs are excessive at scale.

We show how untrusted servers can detect messages on behalf of recipients, and summarize these into a compact encrypted digest that recipients can easily decrypt. These servers operate obliviously and do not learn anything about which messages are addressed to which recipients. Privacy, soundness, and completeness hold even if everyone but the recipient is adversarial and colluding (unlike in prior schemes), and are post-quantum secure.

Our starting point is an asymptotically-efficient approach, using Fully Homomorphic Encryption and homomorphically-encoded Sparse Random Linear Codes. We then address the concrete performance using a bespoke tailoring of lattice-based cryptographic components, alongside various algebraic and algorithmic optimizations. This reduces the digest size to a few bits per message scanned. Concretely, the servers’ cost is a couple of USD per million messages scanned, and the resulting digests can be decoded by recipients in under 20ms. Our schemes can thus practically attain the strongest form of receiver privacy for current applications such as privacy-preserving cryptocurrencies.

We further consider the case of group messaging, where each message may have multiple recipients (e.g., in a group chat or blockchain transaction). Direct use of prior OMR protocols in the group setting increases the servers' work linearly in the group size, rendering it prohibitively costly for large groups.

We thus devise new protocols where the servers' cost grows very slowly with the group size, while recipients' cost is low and independent of the group size. Our approach uses Fully Homomorphic Encryption and other lattice-based techniques, building on and improving on prior work. The efficient handling of groups is attained by encoding multiple recipient-specific clues into a single polynomial or multilinear function that can be efficiently evaluated under FHE, and via preprocessing and amortization techniques.

We formally study several variants of Group Oblivious Message Retrieval (GOMR) and describe corresponding GOMR protocols. Our implementation and benchmarks show, for parameters of interest, cost reductions of orders of magnitude compared to prior schemes. For example, the servers' cost is ~$3.36 per million messages scanned, where each message may address up to 15 recipients.


## License
The OMR library is developed by [Zeyu (Thomas) Liu](https://zeyuthomasliu.github.io/), [Eran Tromer](https://www.tau.ac.il/~tromer/) and [Yunhao Wang](https://wyunhao.github.io/), and is released under the MIT License (see the LICENSE file).


## Model Overview

The following diagram demonstrates the main components of OMR:

![omr](omrHighLevel.png)

Based on this pipeline, we construct two models with respect to GOMR,
which differ in how groups are formed, motivated by different applications:

The first flavor is the Ad-hoc GOMR (AGOMR), which allows the senders to send messages to a group of recipients chosen arbitrarily.
This suits cases such as messaging protocols (e.g., WhatsApp Broadcast Lists)
that let a message be addressed to any set of recipients chosen on the fly, or blockchains where transactions may have many recipients chosen arbitrarily. 

A model overview for AGOMR is shown as below.
<!-- ![agomr_intuition](agomrIntuitionModel.png =250*250) -->
<p align="center" >
<img align="center" src="agomrIntuitionModel.png" width="650" height="400">
</p>

The second flavor is Fixed GOMR (FGOMR), where groups are pre-formed by their members and then addressed collectively.
This suits applications with a notion of persistent groups, such as mailing lists or
group chats.
It also suits blockchains applications in which transactions need to be visible to a set of parties in addition to the recipient (e.g., auditors or jurisdictional law enforcement).

A model overview for FGOMR is shown as below.
<!-- ![fgomr_intuition](fgomrIntuitionModel.png| width=100) -->
<p align="center" >
<img align="center" src="fgomrIntuitionModel.png" width="700" height="400">
</p>

Here, we also briefly summarize the high-level scheme notions as below, where more details are provided in Section 2.1 in GOMR.
In our system, we have a bulletin board (or board), denoted *BB*, that is publicly available contatining *N* messages. Each message is sent from some sender and is addressed to some recipient(s), whose identities are supposed to remain private.

A message consists of a pair (*xi*, *ci*) where *xi* is the message payload to convey, and *ci* is a clue string which helps notify the intended recipient (and only them) that the message is addressed to them.

In OMR, to generate the clue, the sender grabs the target recipient's *clue key*. In GOMR, the sender uses all the individual *clue keys* of the intended recipients, or alternatively, a *group clue key* jointly generated by the intended group of recipients. *Clue keys*, or *group clue keys*, are assumed to be published or otherwise communicated by some authenticated channels (whose details are
outside our scope).

At any time, any potential recipient *p* may want to retrieve the messages in *BB* that are addressed to them. We call these messages pertinent (to *p*), and the rest are impertinent.

A server, called a detector, helps the recipient *p* detect which message indices in *BB* are pertinent to them, or retrieve the payloads of the pertinent messages. This is done obliviously: even a malicious detector learns nothing about which messages are pertinent. The recipient gives the detector their detection key and a bound *ḱ* on the number of pertinent messages they expect to receive. The detector then accumulates all of the pertinent messages in *BB* into string *M*, called the digest, and sends it to the recipient *p*.

The recipient *p* processes *M* to recover all of the pertinent messages with high probability, assuming a semi-honest detector and that the number of pertinent messages did not exceed *ḱ*.

This code implements GOMR schemes (AGOMR3 in sec 6.2 and FGOMR1 in sec 7.3) described in the [GOMR paper](https://eprint.iacr.org/2023/534), which is based on the OMR described in the [OMR paper](https://eprint.iacr.org/2021/1256.pdf) with some optimizations (see sec C).


<!-- ## Construction Overview
The following diagram demonstrates the main components of OMR:

![omr](omrHighLevel.png)


We realize AGOMR using multi-linear function encoding together with other techniques. The detector uses this encoding to homomorphically recover a PVW ciphertext (Step 1 in the following diagram) and proceeds as in OMR (Step 2 and Step 3 in the OMR and AGOMR diagrams).
![agomr](agomrHighLevel.png)


The FGOMR setting is a special case of AGOMR, where having pre-formed groups FGOMR allows for more efficient constructions,
and a stronger Denial-of-Service property (two honest recipients cannot be spammed jointly if they did not agree to join the same group).

We realize FGOMR by replacing the PVW protocols with a key-private Multi-Recipient Encryption (MRE) scheme we construct in the paper. The detector homomorphically decrypts the MRE ciphertexts (Step 1 and Step 2 in the following diagram) and proceeds as in OMR (Step 3 in the OMR and FGOMR diagrams).


![fgomr](fgomrHighLevel.png) -->

## What's in the demo

### Oblivious Message Detection
- Obliviously identify the pertinent messages and pack all their indices into a into a single digest.
- Schemes benchmarked: OMD1p (section 7.2)
- Measured
    - Key size: ~99MB
    - Detector running time, with Intel-HEXL: ~0.021 sec/msg
    - Detector running time, w/o  Intel-HEXL: ~0.030 sec/msg
    - Recipient running time: ~0.005 sec
    - Digest size: ~280KB

### Oblivious Message Retrieval
- Obliviously identify the pertinent messages and pack all their contents into a into a single digest.
- Schemes benchmarked: OMR1p (Section 7.4) and OMR2p (Section 7.5) in [OMR](https://eprint.iacr.org/2021/1256.pdf)
- Measured: 
    - Key sizes: ~129MB
    - detector running time (1-core, with Intel-HEXL): ~0.145 sec/msg and ~0.155 sec/msg
    - detector running time (2-core, with Intel-HEXL): ~0.075 sec/msg and ~0.085 sec/msg
    - detector running time (4-core, with Intel-HEXL): ~0.065 sec/msg and ~0.072 sec/msg
    - detector running time (1-core, w/o  Intel-HEXL): ~0.215 sec/msg and ~0.246 sec/msg
    - detector running time (2-core, w/o  Intel-HEXL): ~0.108 sec/msg and ~0.123 sec/msg
    - detector running time (4-core, w/o  Intel-HEXL): ~0.099 sec/msg and ~0.115 sec/msg
    - recipient running time: ~0.02 sec and ~0.063 sec
    - Digest size: ~560KB

### Group Oblivious Message Retrieval
- Obliviously identify the pertinent messages that are addressed to a group of recipients and pack all their contents into a into a single digest, which will be sent to one of the recipients inside the intended groups.
- Schemes benchmarked (in GOMR): 
    - main schemes AGOMR3 (Section 6.2) (which is GOMR2_ObliviousMultiplexer_BFV in the code) and FGOMR1 (Section 7.4) (which is GOMR2_FG in the code)
    - their corresponding weak version AGOMR2 (Remark 6.2) (which is GOMR2_ObliviousMultiplexer_BFV in the weak branch) and FGOMR2 (Remark 7.4) (which is GOMR2_FG in the weak branch)
- Measured (with parameters in sec 9):
    - Clue sizes (with group size = 15):
        - AGOMR: ~15300 Byte/msg
        - FGOMR: ~1100 Byte/msg
    - Clue key sizes (with group size = 15):
        - AGOMR: 133K per recipient
        - FGOMR: 1.56M per group
    - Detection key size: ~140M
    - Digest size: ~35 Byte/msg
    - Recipient run time: ~0.02 sec
    - Detector run time:
![gomr_detector](detectortimescale.png)


### Parameters 
- OMR: N = 2^19 (or *N* = 500,000 padded to 2^19), k = *ḱ* = 50. Benchmark results on a Google ComputeCloudc2-standard-4instance type (4 hyperthreads of an Intel Xeon 3.10 GHz CPU with 16GB RAM) are reported in Section 10 in [OMR paper](https://eprint.iacr.org/2021/1256.pdf).
- GOMR:  N = 2^15 (or *N* = 32,768), P = 2^60, G' = G+4, k = *ḱ* = 50, other detailed parameters please refer to our paper. Benchmark results for AGOMR with grou size ≥45, we use e8-highmem-64 instance, 64GB RAM (with a 128GB balanced disk), otherwise, we use e2-standard-2 instance type with 8GB RAM. Note that the runtime of the instance e8-highmem-64 is roughly the same as e2-standard-2. Detailed performance report can be found in Section 9 in the [GOMR paper](https://eprint.iacr.org/2023/534).

## Dependencies

The OMR library relies on the following:

- C++ build environment
- CMake build infrastructure
- [SEAL](https://github.com/microsoft/SEAL) library 3.6 or 3.7 and all its dependencies
- [PALISADE](https://gitlab.com/palisade/palisade-release) library release v1.11.2 and all its dependencies (as v1.11.2 is not publicly available anymore when this repository is made public, we use v1.11.3 in the instructions instead)
- [NTL](https://libntl.org/) library 11.4.3 and all its dependencies
- [OpenSSL](https://github.com/openssl/openssl) library on branch OpenSSL_1_1_1-stable
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

OMRDIR=~/OMR   # change OMRDIR to where you want the dependency libraries installed
mkdir -p $OMRDIR

# Now put GOMR_code.zip file is in ~/OMR
# For example, if using GCP instance
# Upload GOMR_code.zip and then do: mv GOMR_code.zip ~/OMR
cd $OMRDIR
git clone https://github.com/ObliviousMessageRetrieval/ObliviousMessageRetrieval
LIBDIR=$OMRDIR/ObliviousMessageRetrieval/build

cd $OMRDIR
git clone -b v1.11.3 https://gitlab.com/palisade/palisade-release
cd palisade-release
mkdir build
cd build
cmake .. -DCMAKE_INSTALL_PREFIX=$LIBDIR
make
sudo make install

# Old OpenSSL used for plain AES function without EVP abstraction
cd $OMRDIR
git clone -b OpenSSL_1_1_1-stable https://github.com/openssl/openssl
cd openssl
./config
make
sudo make install

# Optional
cd $OMRDIR
git clone --branch 1.2.3 https://github.com/intel/hexl
cd hexl
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=$LIBDIR
cmake --build build
sudo cmake --install build

cd $OMRDIR
git clone https://github.com/microsoft/SEAL
cd SEAL
cmake -S . -B build -DCMAKE_INSTALL_PREFIX=$LIBDIR \
-DSEAL_USE_INTEL_HEXL=ON 
cmake --build build
sudo cmake --install build

cd $OMRDIR/ObliviousMessageRetrieval/build
mkdir ../data
mkdir ../data/payloads
mkdir ../data/clues
mkdir ../data/cluePoly
mkdir ../data/processedCM
sudo cmake .. -DCMAKE_PREFIX_PATH=$LIBDIR
sudo make
```

### To Run

```
cd $LIBDIR
# to run our main AGOMR construction: for example, ./OMRdemos agomr 15
sudo ./OMRdemos agomr <group_size>
# to run our main FGOMR construction: for example, ./OMRdemos fgomr 15
sudo ./OMRdemos fgomr <group_size>
```


Below are our benchmarked runtime for AGOMR and FGOMR with the corresponding group sizes as specified in each row:

| Group Size  | Main AGOMR runtime (sec) | Main FGOMR runtime (sec)| 
| ------------- | ------------- | ------------- | 
| 2  | 4833  | 3541 | 
| 4   | 4844  | 3561| 
| 6   | 4861  | 3585| 
| 8   | 4920  | 3620| 
| 10   | 4983  | 3677| 
| 12   | 5050  | 3700| 
| 15   | 5066  | 3711| 
| 25   | 5085  | 3734| 
| 45   | 5511  | 3776| 
| 65   | 6739  | 3972| 
| 85   | 6896  | 3992| 
| 105   | 6981  | 3993| 
| 125   | 9976  | 4003| 
| 150   | 10272  | 4017| 
| 175   | 10278  | 4134| 
| 200   | 10372  | 4171| 
| 225   | 13845  | 4311| 
| 250   | 14225  | 4338| 
| 275   | 21069  | 4394| 
| 300   | 21438  | 4500| 
| 325   | 21454  | 4501| 
| 350   | 21641  | 4501| 
| 375   | 21760  | 4504| 
| 400   | 22100  | 4524| 
