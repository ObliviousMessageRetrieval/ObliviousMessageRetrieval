#include "MRE.h"
#include "client.h"
#include "OMRUtil.h"
#include "MathUtil.h"


////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////// Assistant Function /////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////

// Read in the a/b[i] part as a 1 x partySize RHS vector for Oblivious Multiplexer polynomial.
void prepareClueRhs(vector<vector<int>>& rhs, const vector<PVWCiphertext> clues, bool prepare, const int clueLength) {
    for (int index = 0; index < clueLength; index ++) {
        for (int i = 0; i < (int)rhs.size(); i++) {
            if (index >= (int)clues[i].a.GetLength()) {
                if (prepare) {
                    int temp = clues[i].b[index - clues[i].a.GetLength()].ConvertToInt() - 16384;
                    rhs[i][index] = temp < 0 ? temp + 65537 : temp % 65537;
                } else {
                    rhs[i][index] = clues[i].b[index - clues[i].a.GetLength()].ConvertToInt();
                }
            } else {
                rhs[i][index] = clues[i].a[index].ConvertToInt();
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////// OMR schemes ////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Oblivious Message Retrival
 */
namespace omr
{
    vector<Ciphertext> generateDetectionKey(const SEALContext& context, const size_t& degree,
                                            const PublicKey& BFVpk, const SecretKey& BFVsk,
                                            const PVWsk& regSk, const PVWParam& params) { 
        vector<Ciphertext> switchingKey(params.ell);

        BatchEncoder batch_encoder(context);
        Encryptor encryptor(context, BFVpk);
        encryptor.set_secret_key(BFVsk);

        int tempn = 1;
        for(tempn = 1; tempn < params.n; tempn *= 2){}
        for(int j = 0; j < params.ell; j++){
            vector<uint64_t> skInt(degree);
            for(size_t i = 0; i < degree; i++){
                auto tempindex = i%uint64_t(tempn);
                if(int(tempindex) >= params.n) {
                    skInt[i] = 0;
                } else {
                    skInt[i] = uint64_t(regSk[j][tempindex].ConvertToInt() % params.q);
                }
            }
            Plaintext plaintext;
            batch_encoder.encode(skInt, plaintext);
            encryptor.encrypt_symmetric(plaintext, switchingKey[j]);
        }

        return switchingKey;
    }
}

namespace omr_pir
{
    vector<Ciphertext> generateRotatedDetectionKeys(const SEALContext& context, const size_t& degree,
                                                    const PublicKey& BFVpk, const SecretKey& BFVsk,
                                                    const OPVWsk& regSk, const OPVWParam& params) {
        
        vector<Ciphertext> switchingKeys(params.n);

        BatchEncoder batch_encoder(context);
        Encryptor encryptor(context, BFVpk);
        encryptor.set_secret_key(BFVsk);
        Evaluator evaluator(context);

        for (int cnt = 0; cnt < (int) switchingKeys.size(); cnt++) {
            Plaintext plainInd;
            plainInd.resize(degree);
            plainInd.parms_id() = parms_id_zero;
            for (size_t i = 0; i < degree; i++){
                plainInd.data()[i] = 0;
            }
            plainInd.data()[0] = regSk[cnt].ConvertToInt(); // a constant polynomial encoding each element of sk
            encryptor.encrypt_symmetric(plainInd, switchingKeys[cnt]);
            evaluator.transform_to_ntt_inplace(switchingKeys[cnt]);
        }

        return switchingKeys;
    }
}

namespace omr_take3
{
    Ciphertext generateDetectionKeyForOPVWsk(const SEALContext& context, const size_t& degree,
                                                     const PublicKey& BFVpk, const SecretKey& BFVsk,
                                                     const OPVWsk& regSk, const OPVWParam& params) {
        Ciphertext switchingKey;

        BatchEncoder batch_encoder(context);
        Encryptor encryptor(context, BFVpk);
        encryptor.set_secret_key(BFVsk);

        int tempn = 1;
        for(tempn = 1; tempn < params.n; tempn *= 2){}

        vector<uint64_t> skInt(degree);
        for(size_t i = 0; i < degree; i++){
            auto tempindex = i%uint64_t(tempn);
            if(int(tempindex) >= params.n) {
                skInt[i] = 0;
            } else {
                // skInt[i] = uint64_t(regSk[tempindex].ConvertToInt() % params.q);
                skInt[i] = regSk[tempindex].ConvertToInt();
            }
        }
        Plaintext plaintext;
        batch_encoder.encode(skInt, plaintext);
        encryptor.encrypt_symmetric(plaintext, switchingKey);

        return switchingKey;
    }
}


namespace omr_dos
{
    vector<Ciphertext> generateDetectionKey(const SEALContext& context, const size_t& degree,
                                            const PublicKey& BFVpk, const SecretKey& BFVsk,
                                            const srPKEsk& regSk, const srPKEParam& params) { 
        vector<Ciphertext> switchingKey(params.ell);

        BatchEncoder batch_encoder(context);
        Encryptor encryptor(context, BFVpk);
        encryptor.set_secret_key(BFVsk);

        int tempn = 1;
        for(tempn = 1; tempn < params.n1; tempn *= 2){}
        for(int j = 0; j < params.ell; j++){
            vector<uint64_t> skInt(degree);
            for(size_t i = 0; i < degree; i++){
                auto tempindex = i%uint64_t(tempn);
                if(int(tempindex) >= params.n1) {
                    skInt[i] = 0;
                } else {
                    skInt[i] = uint64_t(regSk[j][tempindex].ConvertToInt() % params.q);
                }
            }
            Plaintext plaintext;
            batch_encoder.encode(skInt, plaintext);
            encryptor.encrypt_symmetric(plaintext, switchingKey[j]);
        }

        return switchingKey;
    }
}


/**
 * @brief Ad-hoc Group Oblivious Message Retrival
 */
namespace agomr
{
    typedef vector<vector<long>> AdhocGroupClue;
    typedef vector<Ciphertext> AdhocDetectionKey;

    struct AdGroupClue{
        vector<vector<uint64_t>> cluePoly; // poly_degree's clues, each is a vector of size (param.n * T') 
        vector<vector<uint64_t>> randomness; // poly_degree's randomness, each is a vector of size (prng_seed_uint64_count)

        AdGroupClue() {}
        AdGroupClue(vector<vector<uint64_t>>& cluePoly, vector<vector<uint64_t>>& randomness)
        : cluePoly(cluePoly), randomness(randomness)
        {}
    };

    // add encrypted extended-targetID as the last switching key based on the original logic
    AdhocDetectionKey generateDetectionKey(const vector<int>& targetId, const SEALContext& context, const size_t& degree, 
                            const PublicKey& BFVpk, const SecretKey& BFVsk, const PVWsk& regSk, const PVWParam& params) {
        
        AdhocDetectionKey switchingKey(params.ell + 1);

        BatchEncoder batch_encoder(context);
        Encryptor encryptor(context, BFVpk);
        encryptor.set_secret_key(BFVsk);

        int tempn = 1;
        for (; tempn < params.n; tempn *= 2) {}
        for (int j = 0; j < params.ell; j++) {
            vector<uint64_t> skInt(degree);
            for (size_t i = 0; i < degree; i++){
                auto tempindex = i%uint64_t(tempn);
                if(int(tempindex) >= params.n) {
                    skInt[i] = 0;
                } else {
                    skInt[i] = uint64_t(regSk[j][tempindex].ConvertToInt() % params.q);
                }
            }
            Plaintext plaintext;
            batch_encoder.encode(skInt, plaintext);
            encryptor.encrypt_symmetric(plaintext, switchingKey[j]);
        }


        if ((int)switchingKey.size() > params.ell) {
            for (tempn = 1; tempn < (int)targetId.size(); tempn *= 2) {} // encrypted the argetId for 1 x (id_size)
            vector<uint64_t> skInt(degree);
            for (size_t i = 0; i < degree; i++) {
                auto tempindex = i % uint64_t(tempn);
                if(int(tempindex) >= (int)targetId.size()) {
		    skInt[i] = 0;
                } else {
                    skInt[i] = uint64_t((targetId[tempindex]) % params.q);
                }
            }
            Plaintext plaintext;
            batch_encoder.encode(skInt, plaintext);
            encryptor.encrypt_symmetric(plaintext, switchingKey[switchingKey.size() - 1]);
        }

        return switchingKey;
    }


    AdhocGroupClue generateClue(const PVWParam& params, vector<PVWCiphertext> clues, vector<vector<int>> ids, bool prepare = false, int clueLength = 454) {
        vector<vector<int>> rhs(ids.size(), vector<int>(clueLength));
        vector<vector<int>> lhs = ids;
        prepareClueRhs(rhs, clues, prepare, clueLength);

        AdhocGroupClue cluePolynomial = equationSolvingRandomBatch(lhs, rhs, -1);

        return cluePolynomial;
    }
}


/**
 * @brief Fixed Group Oblivious Message Retrival
 */
namespace fgomr
{
    typedef mre::MREGroupPK FixedGroupSharedKey;
    typedef mre::MREsk FixedGroupSecretKey;
    typedef vector<Ciphertext> FixedGroupDetectionKey;

    vector<FixedGroupSecretKey> secretKeyGen(const PVWParam& params, const PVWsk& target_secretSK, const mre::MREsharedSK& target_sharedSK) {
        return mre::MREgenerateSK(params, target_secretSK, target_sharedSK);
    }

    FixedGroupSharedKey groupKeyGenAux(const PVWParam& params, vector<FixedGroupSecretKey>& mreSK, prng_seed_type& seed) {
        return mre::MREgeneratePartialPK(params, mreSK, seed);
    } 

    PVWCiphertext genClue(const PVWParam& param, const vector<int>& msg, const FixedGroupSharedKey& gpk, prng_seed_type& compress_seed) {
        PVWCiphertext ct;
        mre::MREEncPK(ct, msg, gpk, param, compress_seed);
        return ct;
    }

    FixedGroupDetectionKey generateDetectionKey(const SEALContext& context, const size_t& degree, const PublicKey& BFVpk, const SecretKey& BFVsk,
                                            const PVWsk& secret_sk, const mre::MREsharedSK& shared_sk, const PVWParam& params, const int partialSize = partial_size_glb, const int partySize = party_size_glb) { 
        FixedGroupDetectionKey switchingKey(params.ell + 1);

        BatchEncoder batch_encoder(context);
        Encryptor encryptor(context, BFVpk);
        encryptor.set_secret_key(BFVsk);

        int tempn_secret = 1, tempn_shared = 1;
        for(tempn_secret = 1; tempn_secret < params.n; tempn_secret *= 2){}
        for(tempn_shared = 1; tempn_shared < partialSize; tempn_shared *= 2){}

        vector<uint64_t> skInt(degree);
        Plaintext plaintext;
        // generate the encrypted secret SK
        for (int j = 0; j < params.ell; j++) {
            for (int i = 0; i < (int) degree; i++) {
                int tempindex = i % tempn_secret;
                if (tempindex >= params.n) {
                    skInt[i] = 0;
                } else { 
                    skInt[i] = secret_sk[j][tempindex].ConvertToInt();
                }
            }

            batch_encoder.encode(skInt, plaintext);
            encryptor.encrypt_symmetric(plaintext, switchingKey[j]);
        }

        // generate the encrypted shared SK
        for (int i = 0; i < (int) degree; i++) {
            int tempIndex = i % tempn_shared;
            if (tempIndex >= partialSize) {
                skInt[i] = 0;
            } else { 
                skInt[i] = shared_sk[tempIndex].ConvertToInt();
            }
        }

        batch_encoder.encode(skInt, plaintext);
        encryptor.encrypt_symmetric(plaintext, switchingKey[switchingKey.size() - 1]);

        return switchingKey;
    }
}
