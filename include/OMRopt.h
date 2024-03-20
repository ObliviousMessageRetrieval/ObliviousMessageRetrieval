#include "PVWToBFVSeal.h"
#include "SealUtils.h"
#include "retrieval.h"
#include "client.h"
#include "LoadAndSaveUtils.h"
#include "OMRUtil.h"
#include <NTL/BasicThreadPool.h>
#include <NTL/ZZ.h>
#include <thread>

void OMR3_opt() {
    size_t poly_modulus_degree = poly_modulus_degree_glb;
    int t = 65537;

    process_u_time.resize(numcores, 0);
    unpack_pv_time.resize(numcores, 0);
    digest_encode_time.resize(numcores, 0);

    int numOfTransactions = numOfTransactions_glb;
    int half_party_size = ceil(((double) party_size_glb) / 2.0);

    OMRthreeM = default_bucket_num_glb * (num_of_pertinent_msgs_glb / 50);
    repeatition_glb = OMRthreeM;

    // cout << "half_party_size: " << half_party_size << endl;
    int payload_size = 306;

    int num_ct_for_buckets = OMRthreeM / default_bucket_num_glb;

    cout << "Preparing database and paramaters...\n";
    // pack each two message into one bfv ciphertext, since 306*2*50 < ring_dim = 32768, where 50 is the upper bound of # pertinent messages
    createDatabase(numOfTransactions * half_party_size, payload_size*2);
    /* createDatabase(numOfTransactions * party_size_glb, payload_size); */
    /* cout << "Finishing createDatabase\n"; */

    // step 1. generate OPVW sk
    // recipient side
    auto params = OPVWParam(512, 400, 0.5, 6, 32);
    if (default_param_set) {
        params = OPVWParam(1024, 65537, 0.5, 2, 32);
    }

    auto sk = OPVWGenerateSecretKey(params);
    auto pk = OPVWGeneratePublicKey(params, sk);

    // step 2. prepare transactions
    vector<int> pertinentMsgIndices;
    auto expected = preparingTransactionsFormal_opt(pertinentMsgIndices, pk, numOfTransactions, num_of_pertinent_msgs_glb,  params);
    /* vector<vector<uint64_t>> expected = {{0}}; */
    /* saveClues_opt_attack(params, 0); */

    /* cout << expected.size() << " pertinent msg: Finishing preparing messages\n"; */
    cout << "Pertient message indices: "<< pertinentMsgIndices << endl;

    // step 3. generate detection key
    // recipient side
    EncryptionParameters parms(scheme_type::bfv);
    auto degree = poly_modulus_degree;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 60, 28, 60,
                                                                     60, 60, 60, 60,
                                                                     60, 60, 60, 60,
                                                                     60, 60, 60});
    if (default_param_set) {
        coeff_modulus = CoeffModulus::Create(poly_modulus_degree, { 60, 55, 60, 60,
                                                                    60, 60, 60, 60,
                                                                    60, 60, 60, 60,
                                                                    60, 60, 22, 60});
    }
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(t);

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

    for (int i = 0; i < params.n; i++) {
        sk[i] = sk[i] == params.q-1 ? 65536 : sk[i];
    }
    Ciphertext switchingKey = omr_take3::generateDetectionKeyForOPVWsk(context, poly_modulus_degree, public_key, secret_key, sk, params);
    for (int i = 0; i < params.n; i++) {
        sk[i] = sk[i] == 65536 ? params.q-1 : sk[i];
    }

    Ciphertext packedSIC;
    
    vector<vector<OPVWCiphertext>> SICPVW_multicore(numcores);
    vector<vector<vector<uint64_t>>> payload_multicore(numcores);
    vector<int> counter(numcores);

    GaloisKeys gal_keys, gal_keys_slotToCoeff, gal_keys_expand;
    vector<int> stepsfirst = {1};
    // only one rot key is needed for full level
    keygen.create_galois_keys(stepsfirst, gal_keys);

    /////////////////////////////////////////////////////////////// Rot Key gen
    vector<int> steps = {0};
    for(int i = 1; i < int(poly_modulus_degree/2); i *= 2) {
	    steps.push_back(i);
    }

    /* cout << "Finishing generating detection keys\n"; */

    /////////////////////////////////////// Level specific keys
    vector<Modulus> coeff_modulus_next = coeff_modulus;
    coeff_modulus_next.erase(coeff_modulus_next.begin() + 4, coeff_modulus_next.end()-1);
    EncryptionParameters parms_next = parms;
    parms_next.set_coeff_modulus(coeff_modulus_next);
    SEALContext context_next = SEALContext(parms_next, true, sec_level_type::none);
    Evaluator evaluator_next(context_next);

    SecretKey sk_next;
    sk_next.data().resize(coeff_modulus_next.size() * degree);
    sk_next.parms_id() = context_next.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_next.size() - 1, sk_next.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_next.data().data() + degree * (coeff_modulus_next.size() - 1));
    KeyGenerator keygen_next(context_next, sk_next); 

    vector<int> slotToCoeff_steps_coeff = {0, 1};
    slotToCoeff_steps_coeff.push_back(sqrt(degree/2));
    keygen_next.create_galois_keys(slotToCoeff_steps_coeff, gal_keys_slotToCoeff);

    //////////////////////////////////////////////////////
    vector<Modulus> coeff_modulus_expand = coeff_modulus;
    coeff_modulus_expand.erase(coeff_modulus_expand.begin() + 2, coeff_modulus_expand.end()-1);
    EncryptionParameters parms_expand = parms;
    parms_expand.set_coeff_modulus(coeff_modulus_expand);
    SEALContext context_expand = SEALContext(parms_expand, true, sec_level_type::none);

    SecretKey sk_expand;
    sk_expand.data().resize(coeff_modulus_expand.size() * degree);
    sk_expand.parms_id() = context_expand.key_parms_id();
    util::set_poly(secret_key.data().data(), degree, coeff_modulus_expand.size() - 1, sk_expand.data().data());
    util::set_poly(
        secret_key.data().data() + degree * (coeff_modulus.size() - 1), degree, 1,
        sk_expand.data().data() + degree * (coeff_modulus_expand.size() - 1));
    KeyGenerator keygen_expand(context_expand, sk_expand); 
    vector<uint32_t> galois_elts;
    auto n = poly_modulus_degree;
    for (int i = 0; i < ceil(log2(poly_modulus_degree)); i++) {
        galois_elts.push_back((n + exponentiate_uint(2, i)) / exponentiate_uint(2, i));
    }
    keygen_expand.create_galois_keys(galois_elts, gal_keys_expand);

    PublicKey public_key_last;
    keygen_next.create_public_key(public_key_last);

    cout << "Database and parameters prepared.\n\n";
    
    ////////////////////////////////////////////////////

    vector<vector<Ciphertext>> packedSICfromPhase1(numcores,vector<Ciphertext>(numOfTransactions/numcores/poly_modulus_degree)); // Assume numOfTransactions/numcores/poly_modulus_degree is integer, pad if needed

    NTL::SetNumThreads(numcores);
    SecretKey secret_key_blank;

    chrono::high_resolution_clock::time_point time_start, time_end, s,e;
    chrono::microseconds time_diff;

    Plaintext pl;
    vector<uint64_t> tm(poly_modulus_degree);
    
    int tempn;
    for(tempn = 1; tempn < params.n; tempn*=2) {}
    vector<Ciphertext> rotated_switchingKey;

    {
    MemoryPoolHandle my_pool = MemoryPoolHandle::New();
    auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));

    rotated_switchingKey.resize(tempn);
    // prepare all rotated switching keys
    s = chrono::high_resolution_clock::now();
    rotated_switchingKey[0] = switchingKey;
    for(int i = 1; i < tempn; i++){
        evaluator.rotate_rows(rotated_switchingKey[i-1], 1, gal_keys, rotated_switchingKey[i]);
    }
    for (int i = 0; i < tempn; i++) {
        evaluator.transform_to_ntt_inplace(rotated_switchingKey[i]);
    }
    e = chrono::high_resolution_clock::now();
    cout << "Preprocess switching key time: " << chrono::duration_cast<chrono::microseconds>(e - s).count() << " us." << endl;

    time_start = chrono::high_resolution_clock::now();

    NTL_EXEC_RANGE(numcores, first, last);
    chrono::high_resolution_clock::time_point s1, e1;
    uint64_t t11 = 0, t22 = 0, bb_to_pv = 0;
    for(int i = first; i < last; i++){
        counter[i] = numOfTransactions/numcores*i;
        
        size_t j = 0;
        while(j < numOfTransactions/numcores/poly_modulus_degree) {
            /* if(!i) */
                /* cout << "Phase 1, Core " << i << ", Batch " << j << endl; */

            Ciphertext packedSIC_temp;
            s1 = chrono::high_resolution_clock::now();
            for (int p = 0; p < party_size_glb; p++) {

	        s = chrono::high_resolution_clock::now();
                loadClues_OPVW(SICPVW_multicore[i], counter[i], counter[i]+poly_modulus_degree, params, p, party_size_glb);
		e = chrono::high_resolution_clock::now();
		t11 += chrono::duration_cast<chrono::microseconds>(e - s).count();

		s = chrono::high_resolution_clock::now();
                packedSIC_temp = obtainPackedSICFromRingLWEClue(secret_key, SICPVW_multicore[i], rotated_switchingKey, relin_keys, gal_keys,
                                                                poly_modulus_degree, context, params, poly_modulus_degree, default_param_set);
                /* cout << "** Noise after phase 1: " << decryptor.invariant_noise_budget(packedSIC_temp) << endl; */

                /* decryptor.decrypt(packedSIC_temp, pl); */
                /* batch_encoder.decode(pl, tm); */
                /* cout << "SIC after rangeCheck: ------------------------------ \n"; */
                /* for (int c = 0; c < (int) poly_modulus_degree; c++) { */
                /*     cout << tm[c] << " "; */
                /* } */
                /* cout << endl; */

                if (p == 0){
                    packedSICfromPhase1[i][j] = packedSIC_temp;
                } else {
                    evaluator.add_inplace(packedSICfromPhase1[i][j], packedSIC_temp);
                }
		e = chrono::high_resolution_clock::now();
		t22 += chrono::duration_cast<chrono::microseconds>(e - s).count();
            }
            j++;
            counter[i] += poly_modulus_degree;
            SICPVW_multicore[i].clear();
            e1 = chrono::high_resolution_clock::now();
	    bb_to_pv += chrono::duration_cast<chrono::microseconds>(e1 - s1).count();
            /* cout << "BB to PV time: " << chrono::duration_cast<chrono::microseconds>(e1 - s1).count() << endl; */
        }
    }

    cout << "ClueToPackedPV time: " << bb_to_pv << " us.\n";
    /* decryptor.decrypt(packedSICfromPhase1[0][0], pl); */
    /* batch_encoder.decode(pl, tm); */
    /* for (int c = 0; c < (int) degree; c++) { */
    /*   /\* cout << tm[c] << " "; *\/ */
    /*   tm[c] = 0; */
    /* } */
    /* tm[10] = 1; */
    /* cout << endl; */

    NTL_EXEC_RANGE_END;
    for (int i = 0; i < tempn; i++) {
        rotated_switchingKey[i].release();
    }
    MemoryManager::SwitchProfile(std::move(old_prof));
    }
    rotated_switchingKey.clear();

    // step 4. detector operations
    vector<vector<Ciphertext>> lhs_multi_ctr(numcores);
    vector<vector<vector<Ciphertext>>> rhs_multi(num_ct_for_buckets);
    for (int c = 0; c < (int) num_ct_for_buckets; c++) {
      rhs_multi[c].resize(numcores, vector<Ciphertext>(half_party_size));
    }
    vector<vector<vector<int>>> bipartite_map(numcores);

    for (auto &i : seed_glb) {
        i = random_uint64();
    }
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions, OMRthreeM, repeatition_glb, seed_glb);

    /* for 32768 (15 bit) messages, partySize = 15 (4 bit), we need 60/16 = 4 acc slots */
    int encode_bit = ceil(log2(party_size_glb + 1));
    int index_bit = log2(numOfTransactions_glb);
    int acc_slots = ceil(encode_bit * index_bit / (16.0));
    /* cout << "Acc slots: " << encode_bit << " " << index_bit << " " << acc_slots << endl; */
    int number_of_ct = ceil(repetition_glb * (acc_slots+1) * num_bucket_glb / ((poly_modulus_degree_glb / num_bucket_glb / (acc_slots+1) * (acc_slots+1) * num_bucket_glb) * 1.0));
    /* cout << "number of ct: " << number_of_ct << endl; */
    
    uint64_t inv = modInverse(degree, t);
    /* cout << "Inv: " << inv << endl; */

    int sq_ct = sqrt(degree/2);
    /* s = chrono::high_resolution_clock::now(); */
    /* vector<Plaintext> U_plain_list(poly_modulus_degree); */
    /* for (int iter = 0; iter < sq_ct; iter++) { */
    /*     for (int j = 0; j < (int) 2*sq_ct; j++) { */
    /*         vector<uint64_t> U_tmp = readUtemp(j*sq_ct + iter, poly_modulus_degree); */
    /*         batch_encoder.encode(U_tmp, U_plain_list[iter * 2*sq_ct + j]); */
    /*         evaluator.transform_to_ntt_inplace(U_plain_list[iter * 2*sq_ct + j], packedSICfromPhase1[0][0].parms_id()); */
    /*     } */
    /* } */
    /* e = chrono::high_resolution_clock::now(); */
    /* cout << "Preprocess U plaintext ntt time: " << chrono::duration_cast<chrono::microseconds>(e - s).count() << endl; */
    

    /* Plaintext plainInd; */
    /* plainInd.resize(poly_modulus_degree); */
    /* plainInd.parms_id() = parms_id_zero; */
    /* for (int i = 0; i < (int) poly_modulus_degree; i++) { */
    /*   plainInd.data()[i] = 0; */
    /* } */
    /* plainInd.data()[10] = 65535; */
    /* plainInd.data()[1000] = 65535; */

    /* batch_encoder.encode(tm, plainInd); */
    /* encryptor.encrypt(plainInd, packedSICfromPhase1[0][0]); */

    /* for (int i = 0; i < 13; i++) { */
    /*   evaluator.mod_switch_to_next_inplace(packedSICfromPhase1[0][0]); */
    /* } */
    NTL_EXEC_RANGE(numcores, first, last);
    chrono::high_resolution_clock::time_point s1, e1;
    for(int i = first; i < last; i++){
        MemoryPoolHandle my_pool = MemoryPoolHandle::New();
        auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
        size_t j = 0;
        counter[i] = numOfTransactions/numcores*i;
        vector<Ciphertext> packSIC_sqrt_list(2*sq_ct);

        while(j < numOfTransactions/numcores/poly_modulus_degree){
            if(!i)
                /* cout << "Phase 2-3, Core " << i << ", Batch " << j << endl; */
            loadPackedData(payload_multicore[i], counter[i], counter[i]+poly_modulus_degree, payload_size*2, half_party_size);
            vector<Ciphertext> templhsctr;
	    vector<vector<Ciphertext>> temprhs(num_ct_for_buckets);
	    for (int c = 0; c < (int) num_ct_for_buckets; c++) {
	      temprhs[c].resize(half_party_size);
	    }
	    
            Ciphertext curr_PackSIC(packedSICfromPhase1[i][j]);
            s1 = chrono::high_resolution_clock::now();
            Ciphertext packSIC_copy(curr_PackSIC);
            evaluator_next.rotate_columns_inplace(packSIC_copy, gal_keys_slotToCoeff);

            packSIC_sqrt_list[0] = curr_PackSIC;
            packSIC_sqrt_list[sq_ct] = packSIC_copy;

            for (int c = 1; c < sq_ct; c++) {
                evaluator_next.rotate_rows(packSIC_sqrt_list[c-1], sq_ct, gal_keys_slotToCoeff, packSIC_sqrt_list[c]);
                evaluator_next.rotate_rows(packSIC_sqrt_list[c-1+sq_ct], sq_ct, gal_keys_slotToCoeff, packSIC_sqrt_list[c+sq_ct]);
            }
            for (int c = 0; c < sq_ct; c++) {
                evaluator_next.transform_to_ntt_inplace(packSIC_sqrt_list[c]);
                evaluator_next.transform_to_ntt_inplace(packSIC_sqrt_list[c+sq_ct]);
            }
            
            /* Ciphertext packSIC_coeff = slotToCoeff(context, context_next, packSIC_sqrt_list, U_plain_list, */
            /*                                        gal_keys_slotToCoeff, 128, degree); */
            Ciphertext packSIC_coeff = slotToCoeff_WOPrepreocess_time(context, context_next, packSIC_sqrt_list,
								      gal_keys_slotToCoeff, process_u_time[i], 128, degree, t, inv);

    	    /* Ciphertext packSIC_coeff; */
    	    /* plainInd.data()[i] = 65535; */
    	    /* encryptor.encrypt(plainInd, packSIC_coeff); */

    	    /* for (int i = 0; i < 13; i++) { */
    	    /*   evaluator.mod_switch_to_next_inplace(packSIC_coeff); */
    	    /* } */

	    e1 = chrono::high_resolution_clock::now();
	    unpack_pv_time += chrono::duration_cast<chrono::microseconds>(e1 - s1).count();
            /* cout << "SlotToCoeff time: " << chrono::duration_cast<chrono::microseconds>(e1 - s1).count() << endl; */
            /* decryptor.decrypt(packSIC_coeff, pl); */
            if (!default_param_set) {
                evaluator.mod_switch_to_next_inplace(packSIC_coeff);
            }
            /* cout << "** Noise after slotToCoeff: " << decryptor.invariant_noise_budget(packSIC_coeff) << endl; */
            /* cout << "SIC plaintext after slotToCoeff: ------------------------------ \n"; */
	    /* decryptor.decrypt(packSIC_coeff, pl); */
            /* for (int c = 0; c < 100; c++) { */
            /*     cout << pl.data()[c] << " "; */
            /* } */
            /* cout << endl; */

            serverOperations3therest_obliviousExpansion(parms_expand, templhsctr, bipartite_map[i], temprhs, packSIC_coeff, payload_multicore[i],
							relin_keys, gal_keys_expand, sk_expand, public_key_last, poly_modulus_degree, context_next, context_expand,
							poly_modulus_degree, counter[i], number_of_ct, party_size_glb, acc_slots+1, true);

            if(j == 0){
                lhs_multi_ctr[i] = templhsctr;
		for (int c = 0; c < (int) num_ct_for_buckets; c++) {
		  for (int m = 0; m < (int) temprhs[0].size(); m++) {
                    rhs_multi[c][i][m] = temprhs[c][m];
		  }
		}
            } else {
                for(size_t q = 0; q < lhs_multi_ctr[i].size(); q++){
                    evaluator.add_inplace(lhs_multi_ctr[i][q], templhsctr[q]);
                }
		for (int c = 0; c < (int) num_ct_for_buckets; c++) {
		  for (int m = 0; m < (int) temprhs[0].size(); m++) {
                    evaluator.add_inplace(rhs_multi[c][i][m], temprhs[c][m]);
		  }
		}
            }
            j++;
            payload_multicore[i].clear();
        }

        MemoryManager::SwitchProfile(std::move(old_prof));
    }
    NTL_EXEC_RANGE_END;

    for(int i = 1; i < numcores; i++){
        for (size_t q = 0; q < lhs_multi_ctr[i].size(); q++) {
            evaluator.add_inplace(lhs_multi_ctr[0][q], lhs_multi_ctr[i][q]);
        }
	for (int c = 0; c < (int) num_ct_for_buckets; c++) {
	  for (int m = 0; m < half_party_size; m++) {
            evaluator.add_inplace(rhs_multi[c][0][m], rhs_multi[c][i][m]);
	  }
	}
    }

    /* cout << "Process U time: " << process_u_time << " us.\n"; */
    uint64_t total_u = 0, total_unpack = 0, total_digest = 0;
    for (int i = 0; i < numcores; i++) {
      total_u += process_u_time[i];
      total_unpack += unpack_pv_time[i];
      total_digest += digest_encode_time[i];
    }
    cout << "PVUnpack time: " << total_unpack - total_u << " us.\n";
    cout << "ExpandedPVToDigest time: " << total_digest << " us.\n";


    /* cout << "** FINAL LHS NOISE before mod: " << decryptor.invariant_noise_budget(lhs_multi_ctr[0][0]) << endl; */
    /* cout << "** FINAL RHS NOISE before mod: " << decryptor.invariant_noise_budget(rhs_multi[0][0][0]) << endl; */
    while(context.last_parms_id() != lhs_multi_ctr[0][0].parms_id()) {
        for(size_t q = 0; q < lhs_multi_ctr[0].size(); q++){
            evaluator.mod_switch_to_next_inplace(lhs_multi_ctr[0][q]);
        }
    }
    while(context.last_parms_id() != rhs_multi[0][0][0].parms_id()) {
      for (int c = 0; c < (int) num_ct_for_buckets; c++) {
        for (int m = 0; m < half_party_size; m++) {
	  evaluator_next.mod_switch_to_next_inplace(rhs_multi[c][0][m]);
        }
      }
    }
    /* cout << "** FINAL LHS NOISE after mod: " << decryptor.invariant_noise_budget(lhs_multi_ctr[0][0]) << endl; */
    /* cout << "** FINAL RHS NOISE after mod: " << decryptor.invariant_noise_budget(rhs_multi[0][0][0]) << endl; */


    stringstream data_streamdg, data_streamdg2;
    auto digsize = 0;
    for (int c = 0; c < (int) num_ct_for_buckets; c++) {
      for (int m = 0; m < half_party_size; m++) {
        digsize += rhs_multi[c][0][m].save(data_streamdg);
      }
    }
    for(size_t q = 0; q < lhs_multi_ctr[0].size(); q++){
        digsize += lhs_multi_ctr[0][q].save(data_streamdg2);
    }
    /* cout << "Digest size: " << digsize << " bytes" << endl; */

    //////// after switching to the last level, mod down to smaller q before sending the digest ////////
    uint64_t small_p = 268369920; // for 28 last noise level
    
    // uint64_t large_p = 281474976317440; // for 48
    // uint64_t large_p = 36028797014704128; // for 55
    /* uint64_t large_p = 1099510054912; // for 40 */

    // if (!default_param_set) {
    uint64_t large_p = 1152921504581877760; // for 60
    // }

    //////////// for compact digest, mod the ciphertext to smaller q (60 --> 28 bit) and then return ////////////
    //////////// so recipient decrypts using a smaller key, and the BFV evaluation use the large key ////////////
    EncryptionParameters bfv_params_small(scheme_type::bfv);
    bfv_params_small.set_poly_modulus_degree(degree);
    auto coeff_modulus_small = CoeffModulus::Create(degree, { 28, 60});
    bfv_params_small.set_coeff_modulus(coeff_modulus_small);
    bfv_params_small.set_plain_modulus(t);

    bfv_params_small.set_random_generator(rng);
    SEALContext seal_context_small(bfv_params_small, true, sec_level_type::none);
    KeyGenerator keygen_small(seal_context_small);

    SecretKey secret_key_small = keygen_small.secret_key();

    
    RandomToStandardAdapter engine(rng->create());
    uniform_int_distribution<uint32_t> dist(0, 100);

    for (int c = 0; c < (int) num_ct_for_buckets; c++) {
      for (int m = 0; m < half_party_size; m++) {
        for (int i = 0; i < (int) degree; i++) {
	  rhs_multi[c][0][m].data(0)[i] = manual_mod_down_rounding(rhs_multi[c][0][m].data(0)[i], dist(engine), small_p+1, large_p+1);
	  rhs_multi[c][0][m].data(1)[i] = manual_mod_down_rounding(rhs_multi[c][0][m].data(1)[i], dist(engine), small_p+1, large_p+1);
        }
	rhs_multi[c][0][m].parms_id_ = seal_context_small.first_parms_id();
      }
    }
    for(size_t q = 0; q < lhs_multi_ctr[0].size(); q++) {
        for (int i = 0; i < (int) degree; i++) {
            lhs_multi_ctr[0][q].data(0)[i] = manual_mod_down_rounding(lhs_multi_ctr[0][q].data(0)[i], dist(engine), small_p+1, large_p+1);
	    lhs_multi_ctr[0][q].data(1)[i] = manual_mod_down_rounding(lhs_multi_ctr[0][q].data(1)[i], dist(engine), small_p+1, large_p+1);
        }
	lhs_multi_ctr[0][q].parms_id_ = seal_context_small.first_parms_id();
      
    }

    //////////// After generating a default small key, we make it aligned with the large key ////////////
    //////////// such that they differ only w.r.t. the modulus                               ////////////

    // below is for confirming the above two primes
    /* inverse_ntt_negacyclic_harvey(secret_key.data().data(), context.key_context_data()->small_ntt_tables()[0]); */
    /* for (int i = 0; i < 10; i++) { */
    /*   cout << secret_key.data()[i] << " "; */
    /* } */
    /* cout << endl; */
    /* seal::util::RNSIter new_key_rns(secret_key.data().data(), degree); */
    /* ntt_negacyclic_harvey(new_key_rns, coeff_modulus.size(), context.key_context_data()->small_ntt_tables()); */

    /* inverse_ntt_negacyclic_harvey(secret_key_small.data().data(), seal_context_small.key_context_data()->small_ntt_tables()[0]); */
    /* for (int i = 0; i < 10; i++) { */
    /*   cout << secret_key_small.data()[i] << " "; */
    /* } */
    /* cout << endl; */
    /* seal::util::RNSIter new_key_rns_small(secret_key_small.data().data(), degree); */
    /* ntt_negacyclic_harvey(new_key_rns_small, coeff_modulus_small.size(), seal_context_small.key_context_data()->small_ntt_tables()); */

    inverse_ntt_negacyclic_harvey(secret_key.data().data(), context.key_context_data()->small_ntt_tables()[0]);
    inverse_ntt_negacyclic_harvey(secret_key_small.data().data(), seal_context_small.key_context_data()->small_ntt_tables()[0]);
    for (int i = 0; i < (int) degree; i++) {
      /* cout << secret_key.data()[i] << " --> "; */
      secret_key_small.data()[i] = (secret_key.data()[i] == large_p) ? small_p : secret_key.data()[i];
      /* cout << secret_key_small.data()[i] << endl; */
    }
    /* cout << endl; */
    seal::util::RNSIter new_key_rns1(secret_key.data().data(), degree);
    ntt_negacyclic_harvey(new_key_rns1, coeff_modulus.size(), context.key_context_data()->small_ntt_tables());
    seal::util::RNSIter new_key_rns_small1(secret_key_small.data().data(), degree);
    ntt_negacyclic_harvey(new_key_rns_small1, coeff_modulus_small.size(), seal_context_small.key_context_data()->small_ntt_tables());

    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    ////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

    
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    cout << "\nDetector running time: " << time_diff.count() - process_u_time << " us." << "\n";

    digsize = 0;
    for (int c = 0; c < (int) num_ct_for_buckets; c++) {
      for (int m = 0; m < half_party_size; m++) {
        digsize += rhs_multi[c][0][m].save(data_streamdg);
      }
    }
    for(size_t q = 0; q < lhs_multi_ctr[0].size(); q++){
        digsize += lhs_multi_ctr[0][q].save(data_streamdg2);
    }
    // cout << "Digest size: " << digsize << " bytes" << endl;

    // step 5. receiver decoding
    bipartiteGraphWeightsGeneration(bipartite_map_glb, weights_glb, numOfTransactions, OMRthreeM, repeatition_glb, seed_glb);
    time_start = chrono::high_resolution_clock::now();
    auto res = receiverDecodingOMR3_omrtake3(lhs_multi_ctr[0], bipartite_map[0], rhs_multi, poly_modulus_degree, secret_key_small, seal_context_small,
                                             numOfTransactions, party_size_glb, half_party_size, acc_slots+1, payload_size*2);
    time_end = chrono::high_resolution_clock::now();
    time_diff = chrono::duration_cast<chrono::microseconds>(time_end - time_start);
    // cout << "\nRecipient running time: " << time_diff.count() << " us." << "\n";

    /* cout << "EXPECTED -------------------------------------------------------- \n" << expected << endl; */
    /* cout << "RESULT ---------------------------------------------------------- \n" << res << endl; */

    if(checkRes(expected, res))
        cout << "Result is correct!" << endl;
    else
        cout << "Overflow" << endl;
    
    for(size_t i = 0; i < res.size(); i++){
    }
}
