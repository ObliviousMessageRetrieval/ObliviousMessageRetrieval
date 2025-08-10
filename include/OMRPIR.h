#include "PVWToBFVSeal.h"
#include "SealUtils.h"
#include "retrieval.h"
#include "client.h"
#include "LoadAndSaveUtils.h"
#include "OMRUtil.h"
#include <NTL/BasicThreadPool.h>
#include <NTL/ZZ.h>
#include <thread>
#include <algorithm>

void OMR_pir() {
    size_t poly_modulus_degree = poly_modulus_degree_glb;

    numcores = 1; // no need to multi-thread now

    process_u_time.resize(numcores, 0);
    unpack_pv_time.resize(numcores, 0);

    int numOfTransactions = numOfTransactions_glb;

    OMRthreeM = default_bucket_num_glb * (num_of_pertinent_msgs_glb / 50);
    repeatition_glb = OMRthreeM;

    int payload_size = 306;


    cout << "Preparing database and paramaters...\n";
    // pack each two message into one bfv ciphertext, since 306*2*50 < ring_dim = 32768, where 50 is the upper bound of # pertinent messages
    createDatabase(numOfTransactions, payload_size);
    /* createDatabase(numOfTransactions * party_size_glb, payload_size); */
    /* cout << "Finishing createDatabase\n"; */

    // step 1. generate OPVW sk
    // recipient side
    auto params = OPVWParam(1024, 786433, 0.5, 2, 80);

    auto sk = OPVWGenerateSecretKey(params);
    auto pk = OPVWGeneratePublicKey(params, sk);


    // step 3. generate detection key
    // recipient side
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 60, 60}); // ideally just 56, since we have no relin/rot key

    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(bfv_Q);

    prng_seed_type seed;
    for (auto &i : seed) {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

    SEALContext context(parms, true, sec_level_type::none);
    /* cout << "primitive root: " << context.first_context_data()->plain_ntt_tables()->get_root() << endl; */
    print_parameters(context); 
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();

    PublicKey public_key;
    keygen.create_public_key(public_key);
    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    cout << "SK: " << sk << endl;
    vector<Ciphertext> switchingKeys = omr_pir::generateRotatedDetectionKeys(context, poly_modulus_degree, public_key, secret_key, sk, params);


    // step 2. prepare transactions
    vector<int> pertinentMsgIndices;
    auto expected = preparingTransactionsFormal_opt(pertinentMsgIndices, pk, numOfTransactions,
                                                    num_of_pertinent_msgs_glb,  params);

    cout << "Pertient message indices: " << pertinentMsgIndices << endl;

    cout << "Database and parameters prepared.\n\n";


    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    

    Ciphertext packedSIC;
    
    vector<vector<OPVWCiphertext>> SICPVW_multicore(numcores);
    vector<vector<vector<uint64_t>>> payload_multicore(numcores);
    vector<int> counter(numcores);


    int num_of_ct = (int) std::max(1, (int) (numOfTransactions/numcores/poly_modulus_degree));
    vector<vector<vector<Ciphertext>>> packedSICfromPhase1(numcores); 
    for (int i = 0; i < numcores; i++) {
        packedSICfromPhase1[i].resize(params.ell);
        for (int l = 0; l < params.ell; l++) {
            packedSICfromPhase1[i][l].resize(num_of_ct);
        }
    }

    NTL::SetNumThreads(numcores);

    chrono::high_resolution_clock::time_point time_start, time_end, ss, ee;
    chrono::microseconds time_diff;
    
    {
    MemoryPoolHandle my_pool = MemoryPoolHandle::New();
    auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));

    time_start = chrono::high_resolution_clock::now();

    NTL_EXEC_RANGE(numcores, first, last);
    chrono::high_resolution_clock::time_point s1, e1;
    for (int i = first; i < last; i++) {
        counter[i] = numOfTransactions/numcores*i;
        
        int j = 0;
        while (j < num_of_ct) {

            vector<Ciphertext> packedSIC_temp(params.ell);
            for (int p = 0; p < party_size_glb; p++) {
                loadClues_OPVW(SICPVW_multicore[i], counter[i], counter[i]+poly_modulus_degree, params);

                computeBplusAS_omr_pir(packedSIC_temp, SICPVW_multicore[i], switchingKeys,
                                       context, params);
            }
            for (int ll = 0; ll < params.ell; ll++) {
                packedSICfromPhase1[i][ll][j] = packedSIC_temp[ll];
            }
            j++;
            counter[i] += poly_modulus_degree;
            SICPVW_multicore[i].clear();
        }
    }

    NTL_EXEC_RANGE_END;
    MemoryManager::SwitchProfile(std::move(old_prof));
    }

    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nDetector running time: " << time_diff.count() << " us." << "\n";

    Plaintext ppp;
    for (int i = 0; i < params.ell; i++) {
        decryptor.decrypt(packedSICfromPhase1[0][i][0], ppp);
        for (int j = 0; j < (int) poly_modulus_degree; j++) {
            cout << ppp.data()[j] << " ";
        }
        cout << endl;
    }
}
