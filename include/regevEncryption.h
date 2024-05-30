#pragma once

#include "SealUtils.h"
#include "math/ternaryuniformgenerator.h"
#include "math/discreteuniformgenerator.h"
#include "math/discretegaussiangenerator.h"
#include <iostream>
using namespace std;
using namespace lbcrypto;
using namespace seal;

struct regevParam{
    int n;
    int q;
    double std_dev;
    int m;
    regevParam(){
        n = 450;
        q = 65537;
        std_dev = 1.3;
        m = 16000; 
    }
    regevParam(int n, int q, double std_dev, int m)
    : n(n), q(q), std_dev(std_dev), m(m)
    {}
};

typedef NativeVector regevSK;

struct regevCiphertext{
    NativeVector a;
    NativeInteger b;
};

typedef vector<regevCiphertext> regevPK;

regevSK regevGenerateSecretKey(const regevParam& param);
regevPK regevGeneratePublicKey(const regevParam& param, const regevSK& sk);
void regevEncSK(regevCiphertext& ct, const int& msg, const regevSK& sk, const regevParam& param, const bool& pk_gen = false);
void regevEncPK(regevCiphertext& ct, const int& msg, const regevPK& pk, const regevParam& param);
void regevDec(int& msg, const regevCiphertext& ct, const regevSK& sk, const regevParam& param);

/////////////////////////////////////////////////////////////////// Below are implementation

regevSK regevGenerateSecretKey(const regevParam& param){
    int n = param.n;
    int q = param.q;
    lbcrypto::TernaryUniformGeneratorImpl<regevSK> tug;
    return tug.GenerateVector(n, q);
}

void regevEncSK(regevCiphertext& ct, const int& msg, const regevSK& sk, const regevParam& param, const bool& pk_gen){
    NativeInteger q = param.q;
    int n = param.n;
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(q);
    ct.a = dug.GenerateVector(n);
    NativeInteger mu = q.ComputeMu();
    for (int i = 0; i < n; ++i) {
        ct.b += ct.a[i].ModMulFast(sk[i], q, mu);
    }
    ct.b.ModEq(q);
    if(!pk_gen)
        msg? ct.b.ModAddFastEq(3*q/4, q) : ct.b.ModAddFastEq(q/4, q);
    DiscreteGaussianGeneratorImpl<NativeVector> m_dgg(param.std_dev);
    ct.b.ModAddFastEq(m_dgg.GenerateInteger(q), q);
}

regevPK regevGeneratePublicKey(const regevParam& param, const regevSK& sk){
    regevPK pk(param.m);
    for(int i = 0; i < param.m; i++){
        regevEncSK(pk[i], 0, sk, param, true);
    }
    return pk;
}

void regevEncPK(regevCiphertext& ct, const int& msg, const regevPK& pk, const regevParam& param){
    prng_seed_type seed;
    for (auto &i : seed) {
        i = random_uint64();
    }

    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    RandomToStandardAdapter engine(rng->create());
    uniform_int_distribution<uint64_t> dist(0, 1);

    NativeInteger q = param.q;
    ct.a = NativeVector(param.n);
    for(size_t i = 0; i < pk.size(); i++){
        if (dist(engine)){
            for(int j = 0; j < param.n; j++){
                ct.a[j].ModAddFastEq(pk[i].a[j], q);
            }
            ct.b.ModAddFastEq(pk[i].b, q);
        }
    }
    msg? ct.b.ModAddFastEq(3*q/4, q) : ct.b.ModAddFastEq(q/4, q);
}

void regevDec(int& msg, const regevCiphertext& ct, const regevSK& sk, const regevParam& param){
    NativeInteger q = param.q;
    int n = param.n;
    NativeInteger inner(0);
    NativeInteger r = ct.b;
    NativeInteger mu = q.ComputeMu();
    for (int i = 0; i < n; ++i) {
        inner += ct.a[i].ModMulFast(sk[i], q, mu);
    }
    r.ModSubFastEq(inner, q);
    r.ModEq(q);

    msg = (r < q/2)? 0 : 1;
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////// Optimized PVW ///////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct OPVWParam{
    int n;
    int q;
    double std_dev;
    int ell;
    int h;
    OPVWParam(){
        n = 450;
        q = 65537;
        std_dev = 1.3;
        ell = 4;
        h = 32;
    }
    OPVWParam(int n, int q, double std_dev, int ell, int h)
    : n(n), q(q), std_dev(std_dev), ell(ell), h(h)
    {}
};

typedef NativeVector OPVWsk;

struct OPVWCiphertext{
    NativeVector a;
    NativeVector b;
};

typedef OPVWCiphertext OPVWpk;

OPVWsk OPVWGenerateSecretKey(const OPVWParam& param, const bool print);
OPVWpk OPVWGeneratePublicKey(const OPVWParam& param, const OPVWsk& sk);
void OPVWEncSK(OPVWCiphertext& ct, const vector<int>& msg, const OPVWsk& sk, const OPVWParam& param, const bool& pk_gen = false);
void OPVWEncPK(OPVWCiphertext& ct, const vector<int>& msg, const OPVWpk& pk, const OPVWParam& param);
void OPVWDec(vector<int>& msg, const OPVWCiphertext& ct, const OPVWsk& sk, const OPVWParam& param);

/////////////////////////////////////////////////////////////////// Below are implementation

OPVWsk OPVWGenerateSecretKey(const OPVWParam& param) { // generate ternary key
    int n = param.n;
    int q = param.q;
    lbcrypto::TernaryUniformGeneratorImpl<regevSK> tug;
    OPVWsk ret = tug.GenerateVector(n, q, param.h);
    return ret;
}

vector<vector<int>> expandRingVector(NativeVector a, int n, int q) {
    vector<vector<int>> res(n);

    for (int cnt = 0; cnt < n; cnt++) {
        res[cnt].resize(n);
        int ind = 0;
        for (int i = cnt; i >= 0 && ind < n; i--) {
            res[cnt][ind] = a[i].ConvertToInt();
            ind++;
        }

        for (int i = n-1; i > cnt && ind < n; i--) {
            res[cnt][ind] = q-a[i].ConvertToInt();
            ind++;
        }
    }

    return res;
}

NativeVector OPVWRingMultiply(NativeVector a, NativeVector b, int n, int q, bool print = false) {
    NativeVector res = NativeVector(n);
    // NativeVector res1 = NativeVector(n);
    // NativeInteger qq(q);
    // NativeInteger mu = qq.ComputeMu();

    vector<vector<int>> expanded_A = expandRingVector(a, n, q);
    for (int i = 0; i < n; i++) {
        long temp = 0;
        for (int j = 0; j < n; j++) {
            temp = (temp + expanded_A[i][j] * b[j].ConvertToInt()) % q;
            temp = temp < 0 ? temp + q : temp;

            // res1[i] += b[j].ModMulFast(expanded_A[i][j], qq, mu);
        }
        res[i] = temp;
    }

    // if (print) {
    // for (int i = 0; i < n; i++) {
    //     cout << res[i] << ", " << res1[i] << "  ";
    // }
    // cout << endl;
    // }

    return res;
}

void OPVWEncSK(OPVWCiphertext& ct, const vector<int>& msg, const OPVWsk& sk, const OPVWParam& param, const bool& pk_gen) {
    NativeInteger q = param.q;
    int n = param.n;
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(q);
    ct.a = dug.GenerateVector(n);
    ct.b = OPVWRingMultiply(ct.a, sk, n, q.ConvertToInt());

    DiscreteGaussianGeneratorImpl<NativeVector> m_dgg(param.std_dev);
    for (int i = 0; i < (int) msg.size(); i++) {
        if(!pk_gen)
            msg[i] ? ct.b[i].ModAddFastEq(3*q/4, q) : ct.b[i].ModAddFastEq(q/4, q);
        ct.b[i].ModAddFastEq(m_dgg.GenerateInteger(q), q);
    }
}

OPVWpk OPVWGeneratePublicKey(const OPVWParam& param, const OPVWsk& sk) {
    OPVWpk pk;
    vector<int> zeros(param.n, 0);

    OPVWEncSK(pk, zeros, sk, param, true);
    return pk;
}

void OPVWEncPK(OPVWCiphertext& ct, const vector<int>& msg, const OPVWpk& pk, const OPVWParam& param) {
    prng_seed_type seed;
    for (auto &i : seed) {
        i = random_uint64();
    }

    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    RandomToStandardAdapter engine(rng->create());

    lbcrypto::TernaryUniformGeneratorImpl<regevSK> tug;
    NativeVector x = tug.GenerateVector(param.n, param.q, param.h);

    NativeInteger q = param.q;
    ct.a = OPVWRingMultiply(pk.a, x, param.n, q.ConvertToInt(), true);
    ct.b = OPVWRingMultiply(pk.b, x, param.n, q.ConvertToInt());

    DiscreteGaussianGeneratorImpl<NativeVector> m_dgg_1(param.std_dev), m_dgg_2(param.std_dev);
    for(int i = 0; i < param.n; i++){
        ct.a[i].ModAddFastEq(m_dgg_1.GenerateInteger(q), q);
        ct.b[i].ModAddFastEq(m_dgg_2.GenerateInteger(q), q);
    }
}

void OPVWDec(vector<int>& msg, const OPVWCiphertext& ct, const OPVWsk& sk, const OPVWParam& param) {
    msg.resize(param.ell);
    NativeInteger q = param.q;
    int n = param.n;

    NativeVector a_SK = OPVWRingMultiply(ct.a, sk, n, q.ConvertToInt());
    for(int j = 0; j < param.ell; j++){
        NativeInteger r = ct.b[j];

        r.ModSubFastEq(a_SK[j], q);
        r.ModEq(q);
        msg[j] = (r < q/2)? 0 : 1;
    }
}


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////// Snake-Eye Resistance PKE ////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////////////////////////////////////////

struct srPKEParam{
  int n1;
  int n2;
  int k;
  int q;
  double std_dev;
  int ell;
  srPKEParam(){
    n1 = 936;
    n2 = 760;
    k = 1;
    q = 65537;
    std_dev = 0.5;
    ell = 3;
  }
  srPKEParam(int n1, int n2, int k, int q, double std_dev, int ell)
    : n1(n1), n2(n2), k(k), q(q), std_dev(std_dev), ell(ell)
  {}
};

typedef vector<NativeVector> srPKEsk;

struct srPKECiphertext{
  NativeVector a;
  NativeVector b;
};

typedef vector<srPKECiphertext> srPKEpk;

srPKEsk srPKEGenerateSecretKey(const srPKEParam& param, const bool print);
srPKEpk srPKEGeneratePublicKey(const srPKEParam& param, const srPKEsk& sk);
void srPKEEncSK(srPKECiphertext& ct, const vector<int>& msg, const srPKEsk& sk, const srPKEParam& param, const bool& pk_gen = false);
void srPKEEncPK(srPKECiphertext& ct, const vector<int>& msg, const srPKEpk& pk, const srPKEParam& param);
void srPKEDec(vector<int>& msg, const srPKECiphertext& ct, const srPKEsk& sk, const srPKEParam& param);

/////////////////////////////////////////////////////////////////// Below are implementation

srPKEsk srPKEGenerateSecretKey(const srPKEParam& param) {
  int n1 = param.n1;
  int q = param.q;
  lbcrypto::TernaryUniformGeneratorImpl<regevSK> tug;
  lbcrypto::DiscreteUniformGeneratorImpl<regevSK> dug;
  dug.SetModulus(q);
  srPKEsk ret(param.ell);

  for (int e = 0; e < param.ell; e++) {
    ret[e] = NativeVector(n1);
    NativeVector ter_part = tug.GenerateVector(n1-param.k, q);
    NativeVector uni_part = dug.GenerateVector(param.k);

    for (int i = 0; i < n1-param.k; i++) {
      ret[e][i] = ter_part[i];
    }
    for (int i = n1-param.k; i < n1; i++) {
      ret[e][i] = uni_part[i - n1 + param.k];
    }
  }
  return ret;
}

void srPKEEncSK(srPKECiphertext& ct, const vector<int>& msg, const srPKEsk& sk, const srPKEParam& param, const bool& pk_gen) {
  NativeInteger q = param.q;
  int n1 = param.n1;
  int ell = param.ell;
  DiscreteUniformGeneratorImpl<NativeVector> dug;
  dug.SetModulus(q);
  ct.a = dug.GenerateVector(n1);
  ct.b = NativeVector(ell);
  NativeInteger mu = q.ComputeMu();
  for(int j = 0; j < ell; j++){
    ct.b[j] = 0;
    for (int i = 0; i < n1; ++i) {
      ct.b[j] += ct.a[i].ModMulFast(sk[j][i], q, mu);
    }
    ct.b[j].ModEq(q);

    if(!pk_gen)
      msg[j]? ct.b[j].ModAddFastEq(3*q/4, q) : ct.b[j].ModAddFastEq(q/4, q);
    DiscreteGaussianGeneratorImpl<NativeVector> m_dgg(param.std_dev);
    ct.b[j].ModAddFastEq(m_dgg.GenerateInteger(q), q);
  }
}

srPKEpk srPKEGeneratePublicKey(const srPKEParam& param, const srPKEsk& sk) {
  srPKEpk pk(param.n2);
  vector<int> zeros(param.ell, 0);

  for(int i = 0; i < param.n2; i++){
    srPKEEncSK(pk[i], zeros, sk, param, true);
  }
  return pk;
}

void srPKEEncPK(srPKECiphertext& ct, const vector<int>& msg, const srPKEpk& pk, const srPKEParam& param) {
  prng_seed_type seed;
  for (auto &i : seed) {
    i = random_uint64();
  }

  auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
  RandomToStandardAdapter engine(rng->create());
  uniform_int_distribution<uint64_t> dist(0, 1);

  NativeInteger q = param.q;
  ct.a = NativeVector(param.n1);
  ct.b = NativeVector(param.ell);
  for (int i = 0; i < param.n2; i++){
    if (dist(engine)){
      for(int j = 0; j < param.n1; j++){
	ct.a[j].ModAddFastEq(pk[i].a[j], q);
      }
      for(int j = 0; j < param.ell; j++){
	ct.b[j].ModAddFastEq(pk[i].b[j], q);
      }
    }
  }

  DiscreteGaussianGeneratorImpl<NativeVector> m_dgg(param.std_dev);
  for (int i = 0; i < param.n1 - param.k; i++) {
    ct.a[i].ModAddFastEq(m_dgg.GenerateInteger(q), q);
  }
  for (int i = 0; i < param.ell; i++){
    ct.b[i].ModAddFastEq(m_dgg.GenerateInteger(q), q);
  }

  for (int j = 0; j < param.ell; j++){
    msg[j]? ct.b[j].ModAddFastEq(3*q/4, q) : ct.b[j].ModAddFastEq(q/4, q);
  }
}

void srPKEDec(vector<int>& msg, const srPKECiphertext& ct, const srPKEsk& sk, const srPKEParam& param) {
  msg.resize(param.ell);
  NativeInteger q = param.q;
  int n1 = param.n1;

  for(int j = 0; j < param.ell; j++){
    NativeInteger inner(0);
    NativeInteger r = ct.b[j];
    NativeInteger mu = q.ComputeMu();
    for (int i = 0; i < n1; ++i) {
      inner += ct.a[i].ModMulFast(sk[j][i], q, mu);
    }
    r.ModSubFastEq(inner, q);
    r.ModEq(q);
    msg[j] = (r < q/2)? 0 : 1;
  }
}


///////////////////////////////////////////////////////////
/////////////////////////////////////////// PVW
///////////////////////////////////////////////////////////

struct PVWParam{
    int n;
    int q;
    double std_dev;
    int m;
    int ell;
    PVWParam(){
        n = 450;
        q = 65537;
        std_dev = 1.3;
        m = 16000; 
        ell = 4;
    }
    PVWParam(int n, int q, double std_dev, int m, int ell)
    : n(n), q(q), std_dev(std_dev), m(m), ell(ell)
    {}
};

typedef vector<NativeVector> PVWsk;

struct PVWCiphertext{
    NativeVector a;
    NativeVector b;
};

typedef vector<PVWCiphertext> PVWpk;

PVWsk PVWGenerateSecretKey(const PVWParam& param, const bool print);
PVWpk PVWGeneratePublicKey(const PVWParam& param, const PVWsk& sk);
void PVWEncSK(PVWCiphertext& ct, const vector<int>& msg, const PVWsk& sk, const PVWParam& param, const bool& pk_gen = false);
void PVWEncPK(PVWCiphertext& ct, const vector<int>& msg, const PVWpk& pk, const PVWParam& param);
void PVWDec(vector<int>& msg, const PVWCiphertext& ct, const PVWsk& sk, const PVWParam& param);

/////////////////////////////////////////////////////////////////// Below are implementation

PVWsk PVWGenerateSecretKey(const PVWParam& param){
    int n = param.n;
    int q = param.q;
    lbcrypto::DiscreteUniformGeneratorImpl<regevSK> dug;
    dug.SetModulus(q);
    PVWsk ret(param.ell);
    for(int i = 0; i < param.ell; i++){
        ret[i] = dug.GenerateVector(n);
    }
    return ret;
}

void PVWEncSK(PVWCiphertext& ct, const vector<int>& msg, const PVWsk& sk, const PVWParam& param, const bool& pk_gen){
    NativeInteger q = param.q;
    int n = param.n;
    int ell = param.ell;
    DiscreteUniformGeneratorImpl<NativeVector> dug;
    dug.SetModulus(q);
    ct.a = dug.GenerateVector(n);
    ct.b = dug.GenerateVector(ell);
    NativeInteger mu = q.ComputeMu();
    for(int j = 0; j < ell; j++){
        ct.b[j] -= ct.b[j];
        for (int i = 0; i < n; ++i) {
            ct.b[j] += ct.a[i].ModMulFast(sk[j][i], q, mu);
        }
        ct.b[j].ModEq(q);

        if(!pk_gen)
            msg[j]? ct.b[j].ModAddFastEq(3*q/4, q) : ct.b[j].ModAddFastEq(q/4, q);
        DiscreteGaussianGeneratorImpl<NativeVector> m_dgg(param.std_dev);
        ct.b[j].ModAddFastEq(m_dgg.GenerateInteger(q), q);
    }
}

PVWpk PVWGeneratePublicKey(const PVWParam& param, const PVWsk& sk){
    PVWpk pk(param.m);
    vector<int> zeros(param.ell, 0);
    for(int i = 0; i < param.m; i++){
        PVWEncSK(pk[i], zeros, sk, param, true);
    }
    return pk;
}

void PVWEncPK(PVWCiphertext& ct, const vector<int>& msg, const PVWpk& pk, const PVWParam& param) {
    prng_seed_type seed;
    for (auto &i : seed) {
        i = random_uint64();
    }

    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    RandomToStandardAdapter engine(rng->create());
    uniform_int_distribution<uint64_t> dist(0, 1);

    NativeInteger q = param.q;
    ct.a = NativeVector(param.n);
    ct.b = NativeVector(param.ell);
    for(size_t i = 0; i < pk.size(); i++){
        if (dist(engine)){
            for(int j = 0; j < param.n; j++){
                ct.a[j].ModAddFastEq(pk[i].a[j], q);
            }
            for(int j = 0; j < param.ell; j++){
                ct.b[j].ModAddFastEq(pk[i].b[j], q);
            }
        }
    }
    for(int j = 0; j < param.ell; j++){
        msg[j]? ct.b[j].ModAddFastEq(3*q/4, q) : ct.b[j].ModAddFastEq(q/4, q);
    }
}

void PVWDec(vector<int>& msg, const PVWCiphertext& ct, const PVWsk& sk, const PVWParam& param){
    msg.resize(param.ell);
    NativeInteger q = param.q;
    int n = param.n;

    for(int j = 0; j < param.ell; j++){
        NativeInteger inner(0);
        NativeInteger r = ct.b[j];
        NativeInteger mu = q.ComputeMu();
        for (int i = 0; i < n; ++i) {
            inner += ct.a[i].ModMulFast(sk[j][i], q, mu);
        }
        r.ModSubFastEq(inner, q);
        r.ModEq(q);
        msg[j] = (r < q/2)? 0 : 1;
    }
}
