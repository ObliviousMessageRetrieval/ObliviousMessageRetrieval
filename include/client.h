#pragma once

#include "seal/seal.h"
#include <algorithm>  
#include <map>

using namespace seal;
#define PROFILE


inline
long power(long x, long y, long m)
{
  if (y == 0)
    return 1;
  long p = power(x, y / 2, m) % m;
  p = (p * p) % m;

  return (y % 2 == 0) ? p : (x * p) % m;
}

inline
long modInverse(long a, long m)
{
  return power(a, m - 2, m);
}

inline
long div_mod(long a, long b, long mod = 65537){
  return (a*modInverse(b, mod)) % mod;
}

// consider index = 010100, partySize = 3, pv_value = 1, the final output would be 110
// as each ceil(log2(partySize+1)) - bits will be mapped back to a single bit {1,0}
// if any ceil(log2(partySize+1)) - bits pattern does not match the pv_value, collision detected
int extractIndexWithoutCollision(uint128_t index, int partySize, int pv_value) {
    int res = 0, counter = 0;

    int nearest_power_two = 1;
    for (; nearest_power_two < partySize+1; nearest_power_two*=2) {}

    while (index) {
      if (index % nearest_power_two) {
	res += 1 << counter;
	if ((int) (index % nearest_power_two) != pv_value)
	  return -1;
      }
      index = (uint128_t) (index >> max(1, (int) (ceil(log2(partySize+1)))));
      counter++;
    }
    return res;

    // while (index) {
    //     if (index & 1) {
    //         res += 1 << counter;
    //         if ((int) (index & 1) != pv_value)
    //             return -1;
    //     }
    //     index = (uint128_t) (index >> max(1, (int) (ceil(log2(partySize+1)))));
    //     counter++;
    // }
    // return res;
}

// Deterministic decoding for OMD
vector<uint64_t> decodeIndicesOMD(const Ciphertext& indexPack, const int& num_of_transactions, const size_t& degree, const SecretKey& secret_key, const SEALContext& context){
    vector<uint64_t> pertinentIndices;
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);
    vector<uint64_t> indexPackint(degree);
    Plaintext plain_result;
    decryptor.decrypt(indexPack, plain_result);
    batch_encoder.decode(plain_result, indexPackint);

    uint64_t counter = 0;
    for(size_t i = 0; i < degree; i++){
        if(indexPackint[i]){
            if(indexPackint[i] & 1){
                pertinentIndices.push_back(counter*degree + i);
            }
            indexPackint[i] >>= 1;
            counter += 1;
            i--;
        } else {
            counter = 0;
        }
    }

    return pertinentIndices;
}

// Deterministic decoding for OMR
// the deterministic encoding for OMD is more efficient, but has limited affect on the overall performance
// param: pertinentIndices - <index, <counter, group_pv_value>>, double layer map
void decodeIndices(map<int, pair<int, int>>& pertinentIndices, const Ciphertext& indexPack, const int& num_of_transactions,
                   const size_t& degree, const SecretKey& secret_key, const SEALContext& context, int partySize = 1) {
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);
    vector<uint64_t> indexPackint(degree);
    Plaintext plain_result;
    decryptor.decrypt(indexPack, plain_result);
    batch_encoder.decode(plain_result, indexPackint);
    int counter = 0;
    int backcounter = (int) (log2(65537) / max(1, (int) (ceil(log2(partySize)))));
    int idx = 0;
    for(int i = 0; i < num_of_transactions;){
        if(!indexPackint[idx])
        {
            idx += 1;
            i += backcounter;
            backcounter = (int) (log2(65537) / max(1, (int) (ceil(log2(partySize)))));
            continue;
        }
        if((indexPackint[idx] & max(1, (int) (ceil(log2(partySize)) - 1))) > 0) // check if that slot is not zero
        {
            pair<int, int> temp(counter++, indexPackint[idx]);
            pertinentIndices.insert(pair<int, pair<int, int>>(i, temp));
        }
        indexPackint[idx] >>= max(1, (int) (ceil(log2(partySize))));
        backcounter -= 1;
        i++;
    }
}

// Randomized decoding for OMR
// TODO: for compatibility, pertinentIndices is a double-layer map, might need refactor to optimize 
void decodeIndicesRandom(map<int, pair<int, int>>& pertinentIndices, const vector<vector<Ciphertext>>& indexPack, const vector<Ciphertext>& indexCounter,
                                     const size_t& degree, const SecretKey& secret_key, const SEALContext& context){
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    int counter = 0;
    int realNumOfPertinentMsg = 0;
    vector<uint64_t> countertemp(degree);
    Plaintext plain_result;
    decryptor.decrypt(indexCounter[0], plain_result);
    batch_encoder.decode(plain_result, countertemp);
    for(size_t i = 0; i < degree; i++){
        realNumOfPertinentMsg += countertemp[i]; // first sumup the counters to see how many messages are there
    }

    for(size_t i = 0; i < indexCounter.size(); i++){
        vector<uint64_t> plain_counter(degree), plain_one(degree), plain_two(degree);
        decryptor.decrypt(indexCounter[i], plain_result);
        batch_encoder.decode(plain_result, plain_counter);
        decryptor.decrypt(indexPack[i][0], plain_result);
        batch_encoder.decode(plain_result, plain_one);
        decryptor.decrypt(indexPack[i][1], plain_result);
        batch_encoder.decode(plain_result, plain_two);
        for(size_t j = 0; j < degree; j++){
            if(plain_counter[j] == 1){ // check the slots without collision
                uint64_t index = plain_one[j]*65537 + plain_two[j];
                if(pertinentIndices.find(index) == pertinentIndices.end()){
                    pair<int, int> temp(counter++, 1);
                    pertinentIndices.insert(pair<int, pair<int, int>>(index, temp));
                }
            }
        }
        if(counter == realNumOfPertinentMsg)
            break;
    }
    if(counter != realNumOfPertinentMsg)
    {
        cerr << "Overflow" << endl;
        exit(1);
    }
}

// Randomized decoding for OMR optimized
void decodeIndicesRandom_opt(map<int, pair<int, int>>& pertinentIndices, const vector<Ciphertext>& buckets, const SecretKey& secret_key,
                             const SEALContext& context, int partySize = 1, size_t slots_per_bucket = 3){
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    int counter = 0, detectedSum = 0;
    int pvSumOfPertinentMsg = 0;
    vector<uint64_t> countertemp(poly_modulus_degree_glb);
    Plaintext plain_result;
    decryptor.decrypt(buckets[0], plain_result);
    batch_encoder.decode(plain_result, countertemp);
    for(int i = (slots_per_bucket - 1) * num_bucket_glb; i < (int) slots_per_bucket * num_bucket_glb; i++){
        pvSumOfPertinentMsg += countertemp[i]; // first sum up the pv_values for all pertinent messages
    }

    ofstream datafile;
    datafile.open("../data/bucket.txt");

    for(int i = 0; i < (int) buckets.size(); i++){ // iterate through all ciphertexts
        vector<uint64_t> plain_bucket(poly_modulus_degree_glb);
        decryptor.decrypt(buckets[i], plain_result);
        batch_encoder.decode(plain_result, plain_bucket);

	datafile << plain_bucket << "\n";
	
        for(int j = 0; j < (int) (poly_modulus_degree_glb / num_bucket_glb / slots_per_bucket); j++){ // iterate through all repetitions encryted in one ciphertext
            for(int k = 0; k < num_bucket_glb; k++) { // iterate through all buckets in one repetition
                uint64_t pv_value = plain_bucket[j * slots_per_bucket * num_bucket_glb + (slots_per_bucket - 1) * num_bucket_glb + k]; // extract the counter value of this bucket
                if ((int) pv_value > partySize) // trivially overflow
                    continue;
                if (pv_value >= 1) {
                    uint128_t index = 0;
                    for (int s = 0; s < (int) (slots_per_bucket-1); s++) {
		        uint64_t curr_slot_value = plain_bucket[j * slots_per_bucket * num_bucket_glb + s * num_bucket_glb + k];
			curr_slot_value = div_mod((long) curr_slot_value, (long) pv_value, 65537);
                        index = (uint128_t) (index * 65537 + curr_slot_value);
                        // index = (uint128_t) (index * 65537 + plain_bucket[j * slots_per_bucket * num_bucket_glb + s * num_bucket_glb + k]);
                    }
                    int real_index = extractIndexWithoutCollision(index, partySize, 1);
                    if(real_index != -1 && pertinentIndices.find(real_index) == pertinentIndices.end())
                    {
                        detectedSum += pv_value;
                        pair<int, int> temp(counter++, pv_value);
                        pertinentIndices.insert(pair<int, pair<int, int>>(real_index, temp));
                    }
                }
                if(detectedSum == pvSumOfPertinentMsg)
                    break;
            }
        }
    }

    if(detectedSum != pvSumOfPertinentMsg)
    {
        cerr << "Overflow: detected pv sum: " << detectedSum << " less than expected: " << pvSumOfPertinentMsg << endl;
        // for (map<int, pair<int, int>>::iterator it = pertinentIndices.begin(); it != pertinentIndices.end(); it++)
        // {
        //     cout << it->first << "," << it->second.second << "  ";
        // }
        // cout << std::endl;
        exit(1);
    }
}

// Construct the RHS of the equations
void formRhs(vector<vector<int>>& rhs, const vector<Ciphertext>& packedPayloads, const SecretKey& secret_key, const size_t& degree, const SEALContext& context,
                         const int num_of_buckets = 64, const int payloadSlots = 306){ // or 306
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);
    vector<uint64_t> rhsint;
    
    for(size_t i = 0; i < packedPayloads.size(); i++){
        vector<uint64_t> temp(degree);
        Plaintext plain_result;
        decryptor.decrypt(packedPayloads[i], plain_result);
        batch_encoder.decode(plain_result, temp);
        // rhsint.insert(rhsint.end(), temp.begin(), temp.end());
	rhsint.insert(rhsint.end(), temp.begin(), temp.begin() + default_bucket_num_glb * payloadSlots);
    }
    
    rhs.resize(num_of_buckets);
    for(int i = 0; i < num_of_buckets; i++){
        rhs[i].resize(payloadSlots, 0);
    }
    for(int i = 0; i < num_of_buckets; i++){
        for(int j = 0; j < payloadSlots; j++){
            rhs[i][j] = int(rhsint[i*payloadSlots + j]);
        }
    }
}

// Construct the LHS of the equations
void formLhsWeights(vector<vector<int>>& lhs, map<int, pair<int, int>>& pertinentIndices, const vector<vector<int>>& bipartite_map, vector<vector<int>>& weights,
                            const int start = 0, const int num_of_buckets = 64) { // start and num_of_buckets are for more buckets
    auto pertinentTransactionNum = pertinentIndices.size();
    lhs.resize(num_of_buckets);
    for(int i = 0; i < num_of_buckets; i++){
        lhs[i].resize(pertinentTransactionNum);
    }

    map<int, pair<int, int>>::iterator itr;
    for(itr = pertinentIndices.begin(); itr != pertinentIndices.end(); ++itr){
        auto ptr = &bipartite_map[itr->first];
        for(size_t j = 0; j < ptr->size(); j++){
            lhs[(*ptr)[j]][itr->second.first] = weights[itr->first][j] * itr->second.second;
        }
    }
}


/////////////////////////// For equation solving

// The following two functions are from: https://www.geeksforgeeks.org/multiplicative-inverse-under-modulo-m/
// To compute x^y under modulo m
inline
void mult_scalar_vec(vector<int>& output, const vector<int>& input, int k){
    output.resize(input.size());
    for(size_t i = 0; i < output.size(); i++){
        long temp = ((long)input[i]*(long)k)%65537;
        output[i] = temp;
        if(output[i] < 0)
            cerr <<temp << " " << k << " " << input[i] << endl;
    } 
}

inline
void subtract_two_vec_inplace(vector<int>& output, const vector<int>& input, int numToSolve = -1){
    if(output.size() != input.size())
    {
        cerr << "substracting size not equal." << endl;
    }
    if(numToSolve == -1) numToSolve = input.size();
    for(int i = 0; i < numToSolve; i++){
        output[i] -= input[i];
        output[i] %= 65537; // modulus
        while(output[i] < 0){
            output[i] += 65537;
        }
    }
}

inline
void get_ratio_mult_and_subtract(vector<int>& outputLhs, const vector<int>& inputLhs,
                                 vector<int>& outputRhs, const vector<int>& inputRhs,
                                 const int whichItem, const int numToSolve = -1)
{
    vector<int> temp(inputLhs.size());
    int k = div_mod(outputLhs[whichItem], inputLhs[whichItem]);
    mult_scalar_vec(temp, inputLhs, k);
    subtract_two_vec_inplace(outputLhs, temp);

    mult_scalar_vec(temp, inputRhs, k);
    subtract_two_vec_inplace(outputRhs, temp, numToSolve);
}

inline
vector<long> singleSolve(const long& a, const vector<int>& toSolve, long mod = 65537){
    long a_rev = modInverse(a, mod);
    vector<long> res(toSolve.size());
    for(size_t i = 0; i < toSolve.size(); i++){
        res[i] = ((long)toSolve[i] * a_rev) % 65537;
    }
    return res;
}

// Performs Gaussian elimination using the functions above
vector<vector<long>> equationSolving(vector<vector<int>>& lhs, vector<vector<int>>& rhs, const int& numToSolve = 306){
    vector<int> recoder(lhs[0].size(), -1);
    vector<vector<long>> res(recoder.size());
    size_t counter = 0;

    while(counter < recoder.size()){
        for(size_t i = 0; i < lhs.size(); i++){
            if (lhs[i][counter] != 0){
                if(find(recoder.begin(), recoder.end(), int(i)) != recoder.end()){
                    continue;
                }
                recoder[counter] = i;
                break;
            }
        }

        if(recoder[counter] == -1) {
            // cout << "no solution" << endl;
            return vector<vector<long>>(0);
        }

        for(size_t i = 0; i < lhs.size(); i++) {
	        if ((lhs[i][counter] != 0) && ((int) i != recoder[counter])) {
                get_ratio_mult_and_subtract(lhs[i], lhs[recoder[counter]], rhs[i], rhs[recoder[counter]], counter, numToSolve);
                if (all_of(lhs[i].begin(), lhs[i].end(), [](int j) { return j==0; })) {
                    lhs.erase(lhs.begin() + i);
                    rhs.erase(rhs.begin() + i);
                    return equationSolving(lhs, rhs, numToSolve);
                }
            }
        }
        counter++;
    }

    counter = 0;
    for(size_t i = 0; i < recoder.size(); i++){
        res[i] = singleSolve(lhs[recoder[counter]][counter], rhs[recoder[counter]]);
        counter++;
    }
    return res;
}


// Pick random values to satisfy multi-variable equation.
// For example, given x + y = 10, we might output {2, 8}.
void assignVariable(RandomToStandardAdapter& engine, vector<vector<long>>& res, vector<int>& lhs, int rhs) {
    uniform_int_distribution<uint64_t> dist(0, 65536);

    if (res.size() != lhs.size())
        cerr << "Coefficient and variable size not match." << endl;

    int lastIndex = lhs.size() - 1;

    for (int i = lhs.size(); i > 0; i--) {
        if (lhs[i-1] != 0) {
            lastIndex = i-1;
            break;
        }
    }

    for (int i = 0; i < (int) lhs.size(); i++) {
        if (lhs[i] != 0 && i != lastIndex) {
            res[i][0] = dist(engine);
            long temp = (rhs - (lhs[i] * res[i][0])) % 65537;
            temp = temp < 0 ? temp + 65537 : temp;
            rhs = temp;
        }
    }

    res[lastIndex][0] = div_mod(rhs % 65537, lhs[lastIndex]);
    if (res[lastIndex][0] < 0)
        res[lastIndex][0] += 65537;
}

// Given solved variables with their values, update the remaining equations.
// For example, with equation; x + y + 2z = 10, and z = 2, updated equation would be x + y = 6.
void updateEquation(vector<vector<long>>& res, vector<vector<int>>& lhs, vector<vector<int>>& rhs) {
  for (int i = 0; i < (int) lhs.size(); i++) {
    for (int j = 0; j < (int) res.size(); j++) {
            if (res[j][0] > 0 && lhs[i][j] != 0) {
                long temp = (rhs[i][0] - lhs[i][j] * res[j][0]) % 65537;
                temp = temp < 0 ? temp + 65537 : temp;
                rhs[i][0] = temp;
                lhs[i][j] = 0;
            }
        }
    }
}

// similar to equationSolving, but assign random values to variable if the equation coefficient matrix is not full rank, i.e. no solution
vector<vector<long>> equationSolvingRandom(vector<vector<int>>& lhs, vector<vector<int>>& rhs, const int& numToSolve = -1) {
    prng_seed_type seed;
    for (auto &i : seed) {
        i = random_uint64();
    }

    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    RandomToStandardAdapter engine(rng->create());

    vector<vector<long>> tryRes = equationSolving(lhs, rhs, -1);
    if (tryRes.empty()) {
        tryRes.resize(lhs[0].size(), vector<long>(1));
        while (!lhs.empty()) {
            assignVariable(engine, tryRes, lhs[lhs.size() - 1], rhs[rhs.size() - 1][0]);
            lhs.pop_back();
            rhs.pop_back();
            updateEquation(tryRes, lhs, rhs);
        }
    }
    return tryRes;
}

// similar to equationSolvingRandom, but batch the rhs to reduce the gaussian eliminations performed.
vector<vector<long>> equationSolvingRandomBatch(vector<vector<int>>& lhs, vector<vector<int>>& rhs, const int& numToSolve = -1) {
    vector<vector<long>> batched_res(rhs[0].size(), vector<long>(lhs[0].size()));
    prng_seed_type seed;
    for (auto &i : seed) {
        i = random_uint64();
    }

    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    RandomToStandardAdapter engine(rng->create());

    vector<vector<long>> tryRes = equationSolving(lhs, rhs, -1);
    if (tryRes.empty()) {
        for (int k = 0; k < (int) rhs[0].size(); k++) { // for each batched rhs, separate the equation system and solve the variables
            vector<vector<int>> single_rhs(rhs.size(), vector<int>(1)), lhs_copy(lhs.size(), vector<int>(lhs[0].size()));
            for (int i = 0; i < (int) rhs.size(); i++) {
                single_rhs[i][0] = rhs[i][k];
            }
            for (int i = 0; i < (int) lhs.size(); i++) {
                for (int j = 0; j < (int) lhs[0].size(); j++) {
                    lhs_copy[i][j] = lhs[i][j];
                }
            }
            vector<vector<long>> single_res(lhs_copy[0].size(), vector<long>(1));
            while (!lhs_copy.empty()) {
                assignVariable(engine, single_res, lhs_copy[lhs_copy.size() - 1], single_rhs[single_rhs.size() - 1][0]);
                lhs_copy.pop_back();
                single_rhs.pop_back();
                updateEquation(single_res, lhs_copy, single_rhs);
            }

            for (int i = 0; i < (int)lhs[0].size(); i++) {
                batched_res[k][i] = single_res[i][0];
            }
        }
    }

    return batched_res;
}
