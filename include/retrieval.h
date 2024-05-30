#pragma once

#include <algorithm>

// one party take log(partySize + 1) bits in one slot
void deterministicIndexRetrieval(Ciphertext& indexIndicator, const vector<Ciphertext>& SIC, const SEALContext& context, 
                                    const size_t& degree, const size_t& start, int partySize = 1) {

    int packSize = (int) (log2(65537) / max(1, (int) (ceil(log2(partySize))))); // number of parties one slot can pack

    BatchEncoder batch_encoder(context);
    Evaluator evaluator(context);
    vector<uint64_t> pod_matrix(degree, 0ULL); 
    if(start + SIC.size() > packSize * degree){
        cerr << "counter + SIC.size should be less, please check " << start << " " << SIC.size() << endl;
        return;
    }

    for(size_t i = 0; i < SIC.size(); i++){
        size_t idx = (i+start) / packSize;
        size_t shift = (i+start) % packSize;
        pod_matrix[idx] = (1 << (max(1, (int) (ceil(log2(partySize)))) * shift));
        Plaintext plain_matrix;
        batch_encoder.encode(pod_matrix, plain_matrix);
        evaluator.transform_to_ntt_inplace(plain_matrix, SIC[i].parms_id());
        if(i == 0 && (start%degree) == 0){
            evaluator.multiply_plain(SIC[i], plain_matrix, indexIndicator);
        }
        else{
            Ciphertext temp;
            evaluator.multiply_plain(SIC[i], plain_matrix, temp);
            evaluator.add_inplace(indexIndicator, temp);
        }
        pod_matrix[idx] = 0ULL;
    }
}

// For randomized index retrieval
// We first have 2 ciphertexts, as we need to represent N ~= 500,000, so sqrt(N) < 65537
// We also need a counter
// Each msg is randomly assigned to one slot
// Then we repeat this process C times and gather partial information to reduce failure probability
void randomizedIndexRetrieval(vector<vector<Ciphertext>>& indexIndicator, vector<Ciphertext>& indexCounters, vector<Ciphertext>& SIC, const SEALContext& context, 
                                        const PublicKey& BFVpk, int counter, const size_t& degree, size_t C){ 
    BatchEncoder batch_encoder(context);
    Evaluator evaluator(context);
    Encryptor encryptor(context, BFVpk);
    vector<uint64_t> pod_matrix(degree, 0ULL);

    prng_seed_type seed;
    for (auto &i : seed) {
        i = random_uint64();
    }

    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    RandomToStandardAdapter engine(rng->create());
    uniform_int_distribution<uint64_t> dist(0, degree-1);

    if((counter%degree) == 0){ // first msg
        indexIndicator.resize(C);
        indexCounters.resize(C);
        for(size_t i = 0; i < C; i++){
            indexIndicator[i].resize(2); // 2 cts allow 65537^2 total messages, which is in general enough so we hard code this.
            encryptor.encrypt_zero(indexIndicator[i][0]);
            encryptor.encrypt_zero(indexIndicator[i][1]);
            encryptor.encrypt_zero(indexCounters[i]);
            evaluator.transform_to_ntt_inplace(indexIndicator[i][0]);
            evaluator.transform_to_ntt_inplace(indexIndicator[i][1]);
            evaluator.transform_to_ntt_inplace(indexCounters[i]);
        }
    }

    for(size_t i = 0; i < SIC.size(); i++){
        for(size_t j = 0; j < C; j++){
            size_t index = dist(engine);

            vector<uint64_t> pod_matrix(degree, 0ULL);
            Ciphertext temp;

            pod_matrix[index] = counter/65537;
            if(pod_matrix[index] == 0){
                // then nothing to do
            } else {
                Plaintext plain_matrix;
                batch_encoder.encode(pod_matrix, plain_matrix);
                evaluator.transform_to_ntt_inplace(plain_matrix, SIC[i].parms_id());
                evaluator.multiply_plain(SIC[i], plain_matrix, temp);
                evaluator.add_inplace(indexIndicator[j][0], temp);
            }

            pod_matrix[index] = counter%65537;
            if(pod_matrix[index] == 0){
                // then nothing to do
            } else {
                Plaintext plain_matrix;
                batch_encoder.encode(pod_matrix, plain_matrix);
                evaluator.transform_to_ntt_inplace(plain_matrix, SIC[i].parms_id());
                evaluator.multiply_plain(SIC[i], plain_matrix, temp);
                evaluator.add_inplace(indexIndicator[j][1], temp);
            }

            pod_matrix[index] = 1;
            if(pod_matrix[index] == 0){
                // then nothing to do
            } else {
                Plaintext plain_matrix;
                batch_encoder.encode(pod_matrix, plain_matrix);
                evaluator.transform_to_ntt_inplace(plain_matrix, SIC[i].parms_id());
                evaluator.multiply_plain(SIC[i], plain_matrix, temp);
                evaluator.add_inplace(indexCounters[j], temp);
            }
        }
        counter += 1;
    }
    return;
}

// consider partySize = 3, index = 6 = 110 in binary representation
// the encoded output would be 010100, as each single bit in the original representation
// will be expanded into ceil(log2(partySize)) - bits
uint128_t encodeIndexWithPartySize(size_t index, int partySize) {
    uint128_t res = 0;
    int counter = 0;
    int shift = max(1, (int) ceil(log2(partySize+1))); // to fit in partySize

    while (index) {
        res += (uint128_t) (index & 1) << (shift * counter);
        counter++;
        index = index>>1;
    }

    return res;
}

// For randomized index retrieval
// We first have 2 ciphertexts, as we need to represent N ~= 500,000, so sqrt(N) < 65537
// We also need a counter
// Each msg is randomly assigned to one accumulator
// Then we repeat this process C times and gather partial information to reduce failure probability
void randomizedIndexRetrieval_opt(vector<Ciphertext>& buckets, vector<Ciphertext>& SIC, const SEALContext& context, 
                                        const PublicKey& BFVpk, int counter, const size_t& degree, size_t C, size_t C_prime,
                                        size_t num_buckets, int partySize = 1, size_t slots_per_bucket = 3, int step_size = 32768,
                                        int expand_bucket_index = 0) {
    BatchEncoder batch_encoder(context);
    Evaluator evaluator(context);
    Encryptor encryptor(context, BFVpk);

    int gap = degree / step_size; // assume both power of 2, default gap = 1024

    prng_seed_type seed;
    for (auto &i : seed) {
        i = random_uint64();
    }

    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    RandomToStandardAdapter engine(rng->create());
    uniform_int_distribution<uint64_t> dist(0, num_buckets-1);

    if ((counter % degree) == 0) { // first msg
        buckets.resize(C_prime);
        for(size_t i = 0; i < C_prime; i++){
            encryptor.encrypt_zero(buckets[i]);
            while(buckets[i].parms_id() != SIC[0].parms_id()){
                evaluator.mod_switch_to_next_inplace(buckets[i]);
            }
            evaluator.transform_to_ntt_inplace(buckets[i]);
        }
    }

    int index_in_curr_ring = counter % degree;
    int index_in_expansion_bucket = index_in_curr_ring % step_size;

    counter = (counter - index_in_curr_ring) + (index_in_expansion_bucket * gap) + expand_bucket_index;

    for(size_t i = 0; i < SIC.size(); i++){
        vector<vector<uint64_t>> pod_matrices(C_prime);
        for(size_t i = 0; i < C_prime; i++){
            pod_matrices[i] = vector<uint64_t>(degree, 0ULL);
        }
        
        Ciphertext temp;
        for(size_t j = 0; j < C; j++){
            size_t index = dist(engine);
            index += (j * slots_per_bucket * num_buckets); // point to the current buckets head for this iteration in the repetition process 
            size_t the_scalar_mtx = index / (degree / num_buckets / slots_per_bucket * num_buckets * slots_per_bucket); // indicate which ciphertext this is
            index %= (degree / num_buckets / slots_per_bucket * num_buckets * slots_per_bucket); // and which slot in this ciphertext

            uint128_t encoded_counter = encodeIndexWithPartySize(counter, partySize);
            for (int s = 0; s < (int) (slots_per_bucket - 1); s++) {
                pod_matrices[the_scalar_mtx][index + (slots_per_bucket - 2 - s) * num_buckets] = encoded_counter % 65537;
                encoded_counter = (uint128_t) (encoded_counter / 65537);
            }
            pod_matrices[the_scalar_mtx][index + (slots_per_bucket - 1) * num_buckets] = 1;
        }

        for(size_t j = 0; j < C_prime; j++){
            Plaintext plain_matrix;
            batch_encoder.encode(pod_matrices[j], plain_matrix);
            evaluator.transform_to_ntt_inplace(plain_matrix, SIC[i].parms_id());
            evaluator.multiply_plain(SIC[i], plain_matrix, temp);
            evaluator.add_inplace(buckets[j], temp);
        }
        
        counter += gap;
    }
    return;
}


// generate the random assignment of each message represented as a bipartite grap
// generate weights for each assignment
void bipartiteGraphWeightsGeneration(vector<vector<int>>& bipartite_map, vector<vector<int>>& weights, const int& num_of_transactions, const int& num_of_buckets, const int& repetition, prng_seed_type& seed){
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    RandomToStandardAdapter engine(rng->create());
    uniform_int_distribution<uint64_t> dist_bucket(0, num_of_buckets-1), dist_weight(0, 65536);

    bipartite_map.clear();
    weights.clear();
    bipartite_map.resize(num_of_transactions);
    weights.resize(num_of_transactions);
    for(int i = 0; i < num_of_transactions; i++)
    {
        bipartite_map[i].resize(repetition, -1);
        weights[i].resize(repetition, -1);
        for(int j = 0; j < repetition; j++){
            int temp = dist_bucket(engine);
            // avoid repeatition
            while(find(bipartite_map[i].begin(), bipartite_map[i].end(), temp) != bipartite_map[i].end()){
                temp = dist_bucket(engine);
            }
            bipartite_map[i][j] = temp;
            // weight is non-zero
            weights[i][j] = dist_weight(engine) + 1;
        }
    }
}

// Note that real payload size = payloadSize / 2
// Note that we use plaintext to do the multiplication which is very fast
// We the first some number of slots as zero
// Note that if we don't know k
// We can still perform this process
// This is because we know one ciphertext has at most 100 combinations
// (actually it's 107 for 612 bytes, but let's assume 100 for simplicity)
// Say if some msg is randomly assigned to position 55
// If after we know k, we need 300 combinations
// we can just randomly assign that message to 55, 155, or 255
// This is the same as randomly chosen from the 300 combinations
// We will always have 100*integer combinations, 
// because it optimizes the efficiency and reduces the failure probability
// as any number from 1 to 100 slots use only one ciphertext
void payloadRetrievalOptimizedwithWeights(vector<vector<Ciphertext>>& results, const vector<vector<uint64_t>>& payloads, const vector<vector<int>>& bipartite_map,
                                          vector<vector<int>>& weights, const vector<Ciphertext>& SIC, const SEALContext& context, const size_t& degree = 32768,
                                          const size_t& start = 0, const size_t& local_start = 0, int expand_bucket_index = 0, int step_size = 32768,
                                          const int payloadSize = 306){ // TODOmulti: can be multithreaded extremely easily
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);
    results.resize(SIC.size());

    int gap = degree / step_size;

    int index_in_curr_ring = local_start;
    int index_in_expansion_bucket = index_in_curr_ring % step_size;

    int new_start = (start - local_start) + (index_in_expansion_bucket * gap) + expand_bucket_index;
    int new_local_start = (index_in_expansion_bucket * gap) + expand_bucket_index;

    for(size_t i = 0; i < SIC.size(); i++){
        results[i].resize(1);
        vector<uint64_t> padded(degree, 0);

        int bipart_map_index = i*gap + new_start;
        int payload_index = i*gap + new_local_start;
        for(size_t j = 0; j < bipartite_map[bipart_map_index].size(); j++){
            auto paddedStart = bipartite_map[bipart_map_index][j]*payloadSize;
            for(size_t k = 0; k < payloads[payload_index].size(); k++){
                auto toAdd = payloads[payload_index][k] *weights[bipart_map_index][j];
                toAdd %= 65537;
                padded[k+paddedStart] += toAdd;
            }
        }
        Plaintext plain_matrix;
        batch_encoder.encode(padded, plain_matrix);
        evaluator.transform_to_ntt_inplace(plain_matrix, SIC[i].parms_id());

        evaluator.multiply_plain(SIC[i], plain_matrix, results[i][0]);  
    }
}

// use only addition to pack
void payloadPackingOptimized(Ciphertext& result, const vector<vector<Ciphertext>>& payloads, const vector<vector<int>>& bipartite_map, const size_t& degree, 
                        const SEALContext& context, const GaloisKeys& gal_keys, const size_t& start = 0, const int payloadSize = 306){
    Evaluator evaluator(context);

    for(size_t i = 0; i < payloads.size(); i++){
        for(size_t j = 0; j < payloads[i].size(); j++){
            if(i == 0 && j == 0 && (start%degree) == 0)
                result = payloads[i][j];
            else{
                for(size_t k = 0; k < 1; k++){ 
                    evaluator.add_inplace(result, payloads[i][j]); 
                }
            }
        }
    }
}


void payloadRetrievalOptimizedwithWeights_omrtake3(vector<vector<vector<Ciphertext>>>& results, const vector<vector<uint64_t>>& payloads, const vector<vector<int>>& bipartite_map,
                                          vector<vector<int>>& weights, const vector<Ciphertext>& SIC, const SEALContext& context, const size_t& degree = 32768,
                                          const size_t& start = 0, const size_t& local_start = 0, int expand_bucket_index = 0, int step_size = 32768,
                                          const int payloadSize = 306, int party_size = party_size_glb){ // TODOmulti: can be multithreaded extremely easily
    Evaluator evaluator(context);
    BatchEncoder batch_encoder(context);

    // number of ciphertexts needed to encode all buckets, for x*53 buckets, x ciphertexts needed
    int num_ct_for_buckets = ((int) bipartite_map[0].size()) / default_bucket_num_glb;
    results.resize(num_ct_for_buckets);
    for (int i = 0; i < num_ct_for_buckets; i++) {
        results[i].resize(SIC.size());
    }

    int gap = degree / step_size;

    int index_in_curr_ring = local_start;
    int index_in_expansion_bucket = index_in_curr_ring % step_size;

    int new_start = (start - local_start) + (index_in_expansion_bucket * gap) + expand_bucket_index;
    int new_local_start = (index_in_expansion_bucket * gap) + expand_bucket_index;

    chrono::high_resolution_clock::time_point s1, e1;
    uint64_t total_party_time = 0;

    for (size_t i = 0; i < SIC.size(); i++) {
        for (int c = 0; c < num_ct_for_buckets; c++) {
	    results[c][i].resize(party_size);
	}

        int bipart_map_index = i*gap + new_start;
        int tmp_payload_index = i*gap + new_local_start;

	s1 = chrono::high_resolution_clock::now();
        for (int h = 0; h < party_size; h++) {
            int payload_index = tmp_payload_index * party_size + h;
	    vector<vector<uint64_t>> padded(num_ct_for_buckets);
	    for (int c = 0; c < (int) padded.size(); c++) {
	        padded[c].resize(degree, 0);
	    }

            for (size_t j = 0; j < bipartite_map[bipart_map_index].size(); j++) {
	        int bucket_ind = bipartite_map[bipart_map_index][j];
		int ct_ind = bucket_ind / default_bucket_num_glb;

                auto paddedStart = (bucket_ind % default_bucket_num_glb) * payloadSize;
                for (size_t k = 0; k < payloads[payload_index].size(); k++) {
                    auto toAdd = payloads[payload_index][k] * weights[bipart_map_index][j];
                    toAdd %= 65537;
                    padded[ct_ind][k + paddedStart] += toAdd;
                }
            }
	    for (int c = 0; c < (int) padded.size(); c++) {
	        Plaintext plain_matrix;
	        batch_encoder.encode(padded[c], plain_matrix);
	        evaluator.transform_to_ntt_inplace(plain_matrix, SIC[i].parms_id());

	        evaluator.multiply_plain(SIC[i], plain_matrix, results[c][i][h]);
	    }
        }
	e1 = chrono::high_resolution_clock::now();
	total_party_time += chrono::duration_cast<chrono::microseconds>(e1 - s1).count();
    }
}

// use only addition to pack
void payloadPackingOptimized_omrtake3(vector<vector<Ciphertext>>& result, const vector<vector<vector<Ciphertext>>>& payloads, const vector<vector<int>>& bipartite_map,
                                      const size_t& degree, const SEALContext& context, const size_t& start = 0) {
    Evaluator evaluator(context);

    for (int c = 0; c < (int) payloads.size(); c++) {
      for (size_t i = 0; i < payloads[0][0].size(); i++) {
        for (size_t j = 0; j < payloads[0].size(); j++) {
	  if (j == 0 && (start%degree) == 0) {
	    result[c][i] = payloads[c][j][i];
	  } else {
	    evaluator.add_inplace(result[c][i], payloads[c][j][i]); 
	  }
	}
      }
    }
}
