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

    numcores = 1; // no need to multi-thread now

    int payload_size = 612;

    if (!is_param_1) {
        bfv_Q = 1032193;
        range_check_pir = 149;
        poly_modulus_degree_glb = 4096;
        numOfTransactions_glb = 4096;
        bfv_Q_prime = 1032193;
    }

    int numOfTransactions = numOfTransactions_glb;

    size_t poly_modulus_degree = poly_modulus_degree_glb;


    cout << "Preparing database and paramaters...\n";
    // pack each two message into one bfv ciphertext, since 306*2*50 < ring_dim = 32768, where 50 is the upper bound of # pertinent messages
    createDatabase(numOfTransactions, payload_size);
    /* createDatabase(numOfTransactions * party_size_glb, payload_size); */
    /* cout << "Finishing createDatabase\n"; */

    // step 1. generate OPVW sk
    // recipient side
    auto params = OPVWParam(900, bfv_Q, 0.6, 1, 80);
    if (!is_param_1) {
        params = OPVWParam(1024, bfv_Q, 0.5, 2, 80);
    }
    
    auto sk = OPVWGenerateSecretKey(params);
    auto pk = OPVWGeneratePublicKey(params, sk);


    // step 3. generate detection key
    // recipient side
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 60}); // ideally just 56, since we have no relin/rot key

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

    int hamming_weight = is_param_1 ? 400 : 128;
    KeyGenerator keygen(context, hamming_weight);
    SecretKey secret_key = keygen.secret_key();

    PublicKey public_key;
    keygen.create_public_key(public_key);
    // RelinKeys relin_keys;
    // keygen.create_relin_keys(relin_keys);
    Encryptor encryptor(context, public_key);
    Evaluator evaluator(context);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    // cout << "SK: " << sk << endl;
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
    uint64_t total_runtime = 0;
    
    cout << "Execute OMR... " << endl;

    vector<bfvCiphertext> mod_res(params.ell);
    vector<uint64_t> sk_mod(poly_modulus_degree_glb);

    for (int iter_omr = 0; iter_omr < (int) (pir_db_size_glb / poly_modulus_degree_glb); iter_omr++) {

    sg = 0;

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
            s1 = chrono::high_resolution_clock::now();
            loadClues_OPVW(SICPVW_multicore[i], counter[i], counter[i]+poly_modulus_degree, params);
            e1 = chrono::high_resolution_clock::now();
            sg += chrono::duration_cast<chrono::microseconds>(e1 - s1).count();

            computeBplusAS_omr_pir(packedSIC_temp, SICPVW_multicore[i], switchingKeys,
                                    context, params);
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


    // below is for confirming the above two primes
    uint64_t big_prime = 0;
    inverse_ntt_negacyclic_harvey(secret_key.data().data(), context.key_context_data()->small_ntt_tables()[0]);
    int i = 0;
    while (!big_prime) {
        big_prime = secret_key.data()[i] > 1 ? secret_key.data()[i] : 0;
        i++;
    }
    // cout << endl;
    for (int i = 0; i < (int) poly_modulus_degree_glb; i++) {
        // sk_mod[i] = secret_key.data()[i] > 1 ? bfv_Q - 1 : secret_key.data()[i];
        sk_mod[i] = secret_key.data()[i] > 1 ? bfv_Q_prime - 1 : secret_key.data()[i];
    }
    seal::util::RNSIter new_key_rns(secret_key.data().data(), poly_modulus_degree_glb);
    ntt_negacyclic_harvey(new_key_rns, coeff_modulus.size(), context.key_context_data()->small_ntt_tables());


    time_start = chrono::high_resolution_clock::now();
    for (int i = 0; i < params.ell; i++) {
        // mod_res[i] = manual_mod_bfv_ciphertext(packedSICfromPhase1[0][i][0], numOfTransactions_glb, big_prime+1, bfv_Q);
        mod_res[i] = manual_mod_bfv_ciphertext(packedSICfromPhase1[0][i][0], numOfTransactions_glb, big_prime+1, bfv_Q_prime);
    }

    time_end = chrono::high_resolution_clock::now();
    time_diff += chrono::duration_cast<chrono::microseconds>(time_end - time_start);

    total_runtime += time_diff.count()-sg;
    }
    cout << "OMR Detector running time: " << total_runtime << " us." << "\n\n";
    
    
    // Note that this decode function below is implemented in a naive way
    // (requiring D^2 time for ring dimension D), only to check correctness.
    // Instead, we estimate the recipient runtime via SEAL decryption with ring dimension D,
    // which uses the optimized DlogD NTT-based algorithm.
    vector<int> decoded_res = decode_pertinent_indices_omr_pir(mod_res, sk_mod, bfv_Q_prime);
    // // vector<int> decoded_res = decode_pertinent_indices_omr_pir(mod_res, sk_mod, bfv_Q);

    // cout << "Decoded pertinent msgs: ---------------\n";
    // for (int i = 0; i < (int) decoded_res.size(); i++) {
    //     if (decoded_res[i]) cout << i << ", ";
    // }
    // cout << endl;

    // cout << decoded_res << endl;

    string command = "";
    if (is_pirana) {
        // command = "../pir/pirana/build/bin/pirexamples -b 1 -l 256 -n 16384 -x 256 -c 0 ";
        command = "../pir/pirana/bin/pirexamples -b 1 -l " + to_string(pir_pertinent_glb) + " -n "
                     + to_string(pir_db_size_glb) + " -x " + to_string(pir_db_entry_size_glb) + " -c " + to_string(is_pirana_comp);
    } else {
        command = "../pir/vectorized_batchpir/build/bin/vectorized_batch_pir "+to_string(pir_pertinent_glb)+" "+to_string(pir_db_size_glb)+" "+to_string(pir_db_entry_size_glb);
    }

    cout << "Execute PIR with command: " << command << endl;
    int ret = std::system(command.c_str());

    if (ret != 0) {
        cout << "Error when running pir.\n";
    }

}
