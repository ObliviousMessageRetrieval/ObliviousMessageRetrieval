#pragma once
#include "regevEncryption.h"
#include "seal/seal.h"
#include <NTL/BasicThreadPool.h>
#include "global.h"
#include "LoadAndSaveUtils.h"
using namespace seal;


// takes a vector of ciphertexts, and mult them all together result in the first element of the vector
// depth optimal using tree-shaped method
inline
void EvalMultMany_inpace(vector<Ciphertext>& ciphertexts, const RelinKeys &relin_keys, const SEALContext& context){ // TODOmulti: can be multithreaded easily
	Evaluator evaluator(context);
	int counter = 0;

	while(ciphertexts.size() != 1){
		counter += 1;
		for(size_t i = 0; i < ciphertexts.size()/2; i++){
			evaluator.multiply_inplace(ciphertexts[i], ciphertexts[ciphertexts.size()/2+i]);
			evaluator.relinearize_inplace(ciphertexts[i], relin_keys);
			if(counter & 1) {
				evaluator.mod_switch_to_next_inplace(ciphertexts[i]);
			}
		}
		if(ciphertexts.size()%2 == 0)
			ciphertexts.resize(ciphertexts.size()/2);
		else{ // if odd, take the last one and mod down to make them compatible
			ciphertexts[ciphertexts.size()/2] = ciphertexts[ciphertexts.size()-1];
			if(counter & 1) {
				evaluator.mod_switch_to_next_inplace(ciphertexts[ciphertexts.size()/2]);
			}
			ciphertexts.resize(ciphertexts.size()/2+1);
		}
	}
}

inline
void EvalMultMany_inpace_modImprove(vector<Ciphertext>& ciphertexts, const RelinKeys &relin_keys, const SEALContext& context, SecretKey& sk){ // TODOmulti: can be multithreaded easily
	Evaluator evaluator(context);
	Decryptor decryptor(context, sk);
	int counter = 0;

	while(ciphertexts.size() != 1){
		for(size_t i = 0; i < ciphertexts.size()/2; i++){
			evaluator.multiply_inplace(ciphertexts[i], ciphertexts[ciphertexts.size()/2+i]);
			evaluator.relinearize_inplace(ciphertexts[i], relin_keys);
			if(counter & 1) {
				evaluator.mod_switch_to_next_inplace(ciphertexts[i]);
			}
		}
		if(ciphertexts.size()%2 == 0)
			ciphertexts.resize(ciphertexts.size()/2);
		else{ // if odd, take the last one and mod down to make them compatible
			ciphertexts[ciphertexts.size()/2] = ciphertexts[ciphertexts.size()-1];
			if(counter & 1) {
				evaluator.mod_switch_to_next_inplace(ciphertexts[ciphertexts.size()/2]);
			}
			ciphertexts.resize(ciphertexts.size()/2+1);
		}
		counter += 1;
	}

}

// innersum up to toCover amount, O(log(toCover)) time
void innerSum_inplace(Ciphertext& output, const GaloisKeys& gal_keys, const size_t& degree,
				const size_t& toCover, const SEALContext& context){
	Evaluator evaluator(context);
	for(size_t i = 1; i < toCover; i*=2){
		Ciphertext temp;
		if(i == degree/2)
		{
			evaluator.rotate_columns(output, gal_keys, temp);
			evaluator.add_inplace(output, temp);
		}
		else
		{
			evaluator.rotate_rows(output, i, gal_keys, temp);
			evaluator.add_inplace(output, temp);
		}
	}
}

// Takes one SIC compressed and expand then into SIC's each encrypt 0/1 in slots up to toExpandNum
void expandSIC(vector<Ciphertext>& expanded, Ciphertext& toExpand, const GaloisKeys& gal_keys, const GaloisKeys& gal_keys_lower,
				const size_t& degree, const SEALContext& context, const SEALContext& context2, const size_t& toExpandNum, const size_t& start = 0){
	BatchEncoder batch_encoder(context);
	Evaluator evaluator(context);
	expanded.resize(toExpandNum);

	vector<uint64_t> pod_matrix(degree, 0ULL);
	pod_matrix[0] = 1ULL;
	Plaintext plain_matrix;
	batch_encoder.encode(pod_matrix, plain_matrix);
	for(size_t i = 0; i < toExpandNum; i++){
		if((i+start) != 0){
			// rotate one slot at a time
			if((i+start) == degree/2){
				evaluator.rotate_columns_inplace(toExpand, gal_keys);
				evaluator.rotate_rows_inplace(toExpand, 1, gal_keys);
			}
			else{
				evaluator.rotate_rows_inplace(toExpand, 1, gal_keys);
			}
		}
		// extract the first slot
		evaluator.multiply_plain(toExpand, plain_matrix, expanded[i]);
		evaluator.mod_switch_to_next_inplace(expanded[i]);
		evaluator.mod_switch_to_next_inplace(expanded[i]);
		// populate to all slots
		innerSum_inplace(expanded[i], gal_keys_lower, degree, degree, context2);
	}
}

// Takes one SIC compressed and expand then into SIC's each encrypt 0/1 in slots up to toExpandNum
void expandSIC_Alt(vector<Ciphertext>& expanded, Ciphertext& toExpand, const GaloisKeys& gal_keys, const GaloisKeys& gal_keys_lower,
				const size_t& degree, const SEALContext& context, const SEALContext& context2, const int toExpandNum, const size_t& start = 0){
	
	if(toExpandNum != step_size_glb){
		cerr << "Not implemented for toExpandNum = " << toExpandNum << endl;
		exit(1);
	}

	BatchEncoder batch_encoder(context);
	Evaluator evaluator(context), evaluator2(context2);
	expanded.resize(toExpandNum);

	// 1. Extract the first 32 element and rotate toExpand by 32, rotate to fill out for every 32 element
	vector<uint64_t> pod_matrix(degree, 0ULL);
	for(int i = 0; i < toExpandNum; i++){
		pod_matrix[i] = 1ULL;
	}
	Plaintext plain_matrix;
	batch_encoder.encode(pod_matrix, plain_matrix);
	Ciphertext first32elements;
	evaluator.multiply_plain(toExpand, plain_matrix, first32elements);
	if(start == degree/2){
		evaluator.rotate_columns_inplace(toExpand, gal_keys);
	}
	evaluator.rotate_rows_inplace(toExpand, toExpandNum, gal_keys);
	evaluator.mod_switch_to_next_inplace(first32elements);

	// evaluator = Evaluator(context2);
	for(size_t i = 32; i < degree; i <<= 1){
		Ciphertext temp;
		if(i == degree/2){
			evaluator2.rotate_columns(first32elements, gal_keys_lower, temp);
		} else {
			evaluator2.rotate_rows(first32elements, i, gal_keys_lower, temp);
		}
		evaluator2.add_inplace(first32elements, temp);
	}

	// 2. Divide it into 8 parts evenly
	vector<Ciphertext> intermediateStep8elements(8);
	for(size_t j = 0; j < 32; j += 4){
		vector<uint64_t> pod_matrix(degree, 0ULL);
		for(size_t i = 0; i < degree; i += 32){
			pod_matrix[i+0+j] = 1ULL;
			pod_matrix[i+1+j] = 1ULL;
			pod_matrix[i+2+j] = 1ULL;
			pod_matrix[i+3+j] = 1ULL;
		}
		Plaintext plain_matrix;
		batch_encoder.encode(pod_matrix, plain_matrix);
		evaluator2.multiply_plain(first32elements, plain_matrix, intermediateStep8elements[j/4]);
		evaluator2.mod_switch_to_next_inplace(intermediateStep8elements[j/4]);

		for(size_t i = 4; i < 32; i <<= 1){
			Ciphertext temp;
			evaluator2.rotate_rows(intermediateStep8elements[j/4], i, gal_keys_lower, temp);
			evaluator2.add_inplace(intermediateStep8elements[j/4], temp);
		}
	}

	// 3. Divide 8 parts into 32 elements
	for(size_t j = 0; j < 4; j += 1){
		vector<uint64_t> pod_matrix(degree, 0ULL);
		for(size_t i = 0; i < degree; i += 4){
			pod_matrix[i+j] = 1ULL;
		}
		Plaintext plain_matrix;
		batch_encoder.encode(pod_matrix, plain_matrix);

		for(size_t k = 0; k < 8; k++){
			evaluator2.multiply_plain(intermediateStep8elements[k], plain_matrix, expanded[k*4 + j]);
			for(size_t i = 1; i < 4; i <<= 1){
				Ciphertext temp;
				evaluator2.rotate_rows(expanded[k*4 + j], i, gal_keys_lower, temp);
				evaluator2.add_inplace(expanded[k*4 + j], temp);
			}
		}
	}
}

/**
 * @brief
 * Given the expanded form of the encrypted ID, we first load the random seed for each message on the bullet board and generate the random matices.
 * And then we multiply the expanded encrypted ID with the random matrices to get the compressed encrypted ID, which is different for each message.
 *
 * @param randomness
 * @param enc_id
 * @param gal_keys
 * @param context
 * @param param
 * @return vector<Ciphertext>
 */
vector<Ciphertext> computeEncryptedCompressedID(Ciphertext& enc_id, uint64_t *total_load, const GaloisKeys& gal_keys,
												const SEALContext& context, const PVWParam& param) {
	Evaluator evaluator(context);
	BatchEncoder batch_encoder(context);

	chrono::high_resolution_clock::time_point time_start, time_end;
	uint64_t rand_total = 0, ntt_total = 0;

	time_start = chrono::high_resolution_clock::now();
	const vector<vector<uint64_t>> randomness = loadOMClue_Randomness(param, 0, poly_modulus_degree_glb,
									  454 * (party_size_glb + secure_extra_length_glb) + prng_seed_uint64_count);;
	time_end = chrono::high_resolution_clock::now();
	total_load += chrono::duration_cast<chrono::microseconds>(time_end - time_start).count();

	int temp_IdSize = 1, tempCom_IdSize = 1;
	for (; temp_IdSize < id_size_glb; temp_IdSize *= 2) {}
	for (; tempCom_IdSize < party_size_glb + secure_extra_length_glb; tempCom_IdSize *= 2) {}

	vector<Ciphertext> compressed_id_ntt(tempCom_IdSize);

	/**
	 * We locally store batch_glb ntt form of the encrypted id, and reuse them when multiplying
	 * the encrypted id with the random matrices.
	 * The reason why we batch process the encrypted id is to perform trade-off between local storage and
	 * number of total multiplications needed.
	 */
	int iteration_ntt = ceil(temp_IdSize / batch_ntt_glb);
	int iteration_cm = ceil(poly_modulus_degree_glb / batch_cm_glb);
	Ciphertext enc_id_ntt;

	for (int it_ntt = 0; it_ntt < iteration_ntt; it_ntt++) {
		for (int it_cm = 0; it_cm < iteration_cm; it_cm++) {
			int start = it_cm*batch_cm_glb, end = (it_cm+1)*batch_cm_glb;

			time_start = chrono::high_resolution_clock::now();
			vector<unsigned char*> random_keys(end-start);
			vector<AES_KEY> aes_keys(end-start);

			for (int i = 0; i < end-start; i ++) {
				random_keys[i] = (unsigned char *) malloc(sizeof(unsigned char) * AES_KEY_SIZE);
			}
			batchLoadRandomSeeds(param, start, end, random_keys);
			for (int i = 0; i < end-start; i ++) {
				AES_set_encrypt_key(random_keys[i], 128, &aes_keys[i]);
			}
			time_end = chrono::high_resolution_clock::now();
			cout << "batchLoadRandomSeeds time: " << chrono::duration_cast<chrono::microseconds>(time_end - time_start).count() << " us." << endl;

			unsigned char out[32];
			unsigned char* input_buffer;
			uint64_t input[2];
			input[1] = 0;
			int col_max = id_size_glb, row_max = party_size_glb + secure_extra_length_glb;
			for (int j = it_ntt*batch_ntt_glb; j < (it_ntt+1)*batch_ntt_glb; j++) {
				evaluator.transform_to_ntt(enc_id, enc_id_ntt);
				for (int i = 0; i < tempCom_IdSize; i++) {
					vector<uint64_t> vectorOfZ(poly_modulus_degree_glb);

					time_start = chrono::high_resolution_clock::now();
					for (int z_index = 0; z_index < (int) poly_modulus_degree_glb;z_index++) {
						int row_index = (i + z_index) % tempCom_IdSize;
						int col_index = (j + z_index) % temp_IdSize;
						if (row_index >= row_max || col_index >= col_max ||
							z_index < start || z_index >= end) {
							vectorOfZ[z_index] = 0;
						} else {//load the transpose
							input[0] = col_index * row_max + row_index;
							input_buffer = (unsigned char*)input;
							AES_ecb_encrypt(input_buffer, out, &aes_keys[z_index], AES_ENCRYPT);
							vectorOfZ[z_index] = convertChar2Uint64(out, 8);
						}
					}
					time_end = chrono::high_resolution_clock::now();
					rand_total += chrono::duration_cast<chrono::microseconds>(time_end - time_start).count();

					// use the last switchingKey encrypting targetId with extended id_size as one unit, and rotate
					Plaintext plaintext;
					batch_encoder.encode(vectorOfZ, plaintext);
					time_start = chrono::high_resolution_clock::now();
					evaluator.transform_to_ntt_inplace(plaintext, enc_id_ntt.parms_id());
					time_end = chrono::high_resolution_clock::now();
					ntt_total += chrono::duration_cast<chrono::microseconds>(time_end - time_start).count();

					if (j == 0 && it_ntt == 0 && it_cm == 0) {
						evaluator.multiply_plain(enc_id_ntt, plaintext, compressed_id_ntt[i]);
					} else {
						Ciphertext temp;
						evaluator.multiply_plain(enc_id_ntt, plaintext, temp);
						evaluator.add_inplace(compressed_id_ntt[i], temp);
					}
				}
				evaluator.rotate_rows_inplace(enc_id, 1, gal_keys);
			}

			for (int i = 0; i < end-start; i ++) {
				free(random_keys[i]);
			}
		}
	}

	cout << "Generate Random element via AES counter total time: " << rand_total << " us.\n";
	cout << "ntt transform for random matrix total time: " << ntt_total << " us.\n";
	return compressed_id_ntt;
}

/**
 * @brief compute b - as with packed swk but also only requires one rot key
 *
 * @param output computed b-aSK ciphertexts (ell ciphertexts for each message)
 * @param cluePoly flatten cluePoly for each message
 * @param switchingKey encryptedSK with encrypted ID as the last switching key
 * @param relin_keys relinear key
 * @param gal_keys galois key
 * @param context SEAL context for evaluator and encoder
 * @param param PVWParam
 */
void computeBplusASPVWOptimizedWithCluePoly(vector<Ciphertext>& output, vector<Ciphertext>& switchingKey,
											const RelinKeys& relin_keys, const GaloisKeys& gal_keys, const SEALContext& context,
											const PVWParam& param, uint64_t *total_plain_ntt, uint64_t *total_load) {

	MemoryPoolHandle my_pool = MemoryPoolHandle::New(true);
	auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));

	int tempn, tempId;
	chrono::microseconds ntt_total(0), ct_total(0), ct_total2(0);
	chrono::high_resolution_clock::time_point time_start, time_end, ntt_start, ntt_end, half_start, half_end;

	time_start = chrono::high_resolution_clock::now();
	vector<Ciphertext> compressed_id_ntt = computeEncryptedCompressedID(switchingKey[switchingKey.size() - 1], total_load,
																		gal_keys, context, param);
	time_end = chrono::high_resolution_clock::now();
	cout << "Compression id time: " << chrono::duration_cast<chrono::microseconds>(time_end - time_start).count() << " us." << endl;

	Evaluator evaluator(context);
	BatchEncoder batch_encoder(context);
	
	cout << "after compression id..." << endl;

	half_start = chrono::high_resolution_clock::now();

	for (tempn = 1; tempn < param.n; tempn *= 2) {}
	for (tempId = 1; tempId < party_size_glb + secure_extra_length_glb; tempId *= 2) {}

	int iteration_cm = ceil(poly_modulus_degree_glb / batch_cm_glb);

	vector<vector<uint64_t>> cluePoly;

	/**
	 * @brief when i = 0; partial_a encrypted (a_00, a_11, a_22, ...)
	 * when i = 1; partial_a encrypted (a_01, a_12, a_23, ...)
	 * so that in the first iteration_ntt, we have (a_00, a_11, a_22, ...) * (sk0, sk1, sk2, ...), and
	 * in the second iteration_ntt, we have (a_01, a_12, a_23, ...) * (sk1, sk2, sk3, ...).
	 * Eventually when we sum them up, we would have the sum if inner product on each entry:
	 * --> (A0*sk, A1*sk, ...) = (b0, b1, ...) (in all ell such vectors)
	 */
	for (int it_cm = 0; it_cm < iteration_cm; it_cm++) {
		int start = it_cm*batch_cm_glb, end = (it_cm+1)*batch_cm_glb;
		time_start = chrono::high_resolution_clock::now();
		cluePoly = loadOMClue_CluePoly(param, start, end, 454 * (party_size_glb + secure_extra_length_glb));
		time_end = chrono::high_resolution_clock::now();
		*total_load += chrono::duration_cast<chrono::microseconds>(time_end - time_start).count();
		cout << "batch load clue: " << start << " to " << end << endl;

		for (int i = 0; i < tempn; i++) {
			Ciphertext partial_a;
			for (int id_index = 0; id_index < tempId; id_index++) {
				vector<uint64_t> vectorOfA(poly_modulus_degree_glb);
				// cluePoly[i][j] = cluePoly.size() x (party_size_glb + secure_extra_length_glb)
				// where, the row: newCluePoly[i] = i-th msg, (i + j) % tempn row of the original matrix
				for (int j = 0; j < (int) poly_modulus_degree_glb; j++) {
					int row_index = (j + i) % tempn;
					int col_index = (j + id_index) % (tempId);
					if (row_index >= param.n || col_index >= party_size_glb + secure_extra_length_glb || j < start || j >= end) {
						vectorOfA[j] = 0;
					} else {
						vectorOfA[j] = cluePoly[j % batch_cm_glb][row_index * (party_size_glb + secure_extra_length_glb) + col_index];
					}
				}

				// use the last switchingKey encrypting targetId with extended id_size_glbid-size as one unit, and rotate
				Plaintext plaintext;
				batch_encoder.encode(vectorOfA, plaintext);

				time_start = chrono::high_resolution_clock::now();
				evaluator.transform_to_ntt_inplace(plaintext, compressed_id_ntt[id_index].parms_id());
				time_end = chrono::high_resolution_clock::now();
				*total_plain_ntt += chrono::duration_cast<chrono::microseconds>(time_end - time_start).count();

				ntt_start = chrono::high_resolution_clock::now();
				if (id_index == 0) {
					evaluator.multiply_plain(compressed_id_ntt[id_index], plaintext, partial_a);
				} else {
					Ciphertext temp;
					evaluator.multiply_plain(compressed_id_ntt[id_index], plaintext, temp);
					evaluator.add_inplace(partial_a, temp);
				}
				ntt_end = chrono::high_resolution_clock::now();
				ntt_total += chrono::duration_cast<chrono::microseconds>(ntt_end - ntt_start);
			}

			evaluator.transform_from_ntt_inplace(partial_a);

			// perform ciphertext multi with switchingKey encrypted SK with [450] as one unit, and rotate
			for(int j = 0; j < param.ell; j++) {
				time_start = chrono::high_resolution_clock::now();
				if(i == 0 && it_cm == 0) {
					evaluator.multiply(switchingKey[j], partial_a, output[j]);
				}
				else {
					Ciphertext temp;
					evaluator.multiply(switchingKey[j], partial_a, temp);
					evaluator.add_inplace(output[j], temp);
				}
				time_end = chrono::high_resolution_clock::now();
				ct_total += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
				evaluator.relinearize_inplace(output[j], relin_keys);
				// rotate one slot at a time
				evaluator.rotate_rows_inplace(switchingKey[j], 1, gal_keys);
				time_end = chrono::high_resolution_clock::now();
				ct_total2 += chrono::duration_cast<chrono::microseconds>(time_end - time_start);
			}
		}
	}

	cout << "Average ntt plain multi: " << ntt_total.count() / tempn / tempId << endl;
	cout << "Average ciphertext multi: " << ct_total.count() / tempn / param.ell << endl;
	cout << "Average ciphertext multi2: " << ct_total2.count() / tempn / param.ell << endl;

	// multiply (encrypted Id) with ell different (clue poly for b)
	vector<Ciphertext> b_parts(param.ell);
	for (int it_cm = 0; it_cm < iteration_cm; it_cm++) {
		int start = it_cm*batch_cm_glb, end = (it_cm+1)*batch_cm_glb;
		// time_start = chrono::high_resolution_clock::now();
		// vector<vector<uint64_t>> cluePoly = loadOMClue_CluePoly(param, start, end, 454 * (party_size_glb + secure_extra_length_glb));
		// time_end = chrono::high_resolution_clock::now();
		// total_load += chrono::duration_cast<chrono::microseconds>(time_end - time_start).count();

		for (int i = 0; i < tempId; i++) {
			for (int e = 0; e < param.ell; e++) {
				vector<uint64_t> vectorOfB(poly_modulus_degree_glb);
				for (int j = 0; j < (int) poly_modulus_degree_glb; j++) {
					int the_index = (i + j) % tempId;
					if (the_index >= party_size_glb + secure_extra_length_glb || j < start || j >= end) {
						vectorOfB[j] = 0;
					} else {
						vectorOfB[j] = cluePoly[j % batch_cm_glb][(param.n + e) * (party_size_glb + secure_extra_length_glb) + the_index];
					}
				}

				Plaintext plaintext;
				batch_encoder.encode(vectorOfB, plaintext);

				time_start = chrono::high_resolution_clock::now();
				evaluator.transform_to_ntt_inplace(plaintext, compressed_id_ntt[i].parms_id());
				time_end = chrono::high_resolution_clock::now();
				*total_plain_ntt += chrono::duration_cast<chrono::microseconds>(time_end - time_start).count();

				if (i == 0 && it_cm == 0) {
					evaluator.multiply_plain(compressed_id_ntt[i], plaintext, b_parts[e]);
				} else {
					Ciphertext temp;
					evaluator.multiply_plain(compressed_id_ntt[i], plaintext, temp);
					evaluator.add_inplace(b_parts[e], temp);
				}
				evaluator.rotate_rows_inplace(switchingKey[switchingKey.size() - 1], 1, gal_keys);
			}
		}
	}

	time_start = chrono::high_resolution_clock::now();
	for (int e = 0; e < param.ell; e++) {
		evaluator.transform_from_ntt_inplace(b_parts[e]);
	}
	time_end = chrono::high_resolution_clock::now();
	*total_plain_ntt += chrono::duration_cast<chrono::microseconds>(time_end - time_start).count();

	// compute a*SK - b with ciphertexts
	for(int i = 0; i < param.ell; i++){
		evaluator.negate_inplace(b_parts[i]);
		evaluator.add_inplace(output[i], b_parts[i]);
		evaluator.mod_switch_to_next_inplace(output[i]);
	}
	MemoryManager::SwitchProfile(std::move(old_prof));

	half_end = chrono::high_resolution_clock::now();
	cout << "Time for operation after compression id: " << chrono::duration_cast<chrono::microseconds>(half_end - half_start).count() << " us.\n";
}


// compute b - aSK with packed swk but also only requires one rot key
void computeBplusASPVWOptimized(vector<Ciphertext>& output, const vector<PVWCiphertext>& toPack, vector<Ciphertext>& switchingKey, const GaloisKeys& gal_keys,
								const SEALContext& context, const PVWParam& param, const int partialSize = partial_size_glb, const int partySize = party_size_glb) {
	MemoryPoolHandle my_pool = MemoryPoolHandle::New(true);
	auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));

	int tempn, sk_size = param.n - partialSize + partialSize * partySize;
	for(tempn = 1; tempn < sk_size; tempn*=2){}

	Evaluator evaluator(context);
	BatchEncoder batch_encoder(context);
	size_t slot_count = batch_encoder.slot_count();
	if(toPack.size() > slot_count){
		cerr << "Please pack at most " << slot_count << " PVW ciphertexts at one time." << endl;
		return;
	}

	for(int i = 0; i < tempn; i++){
		for(int l = 0; l < param.ell; l++){
			vector<uint64_t> vectorOfInts(toPack.size());
			for(int j = 0; j < (int)toPack.size(); j++){
				int the_index = (i + j) % tempn;
				if(the_index >= sk_size) {
					vectorOfInts[j] = 0;
				} else if (the_index >= param.n - partialSize) {// load extended_A part
					the_index += l * partialSize * partySize;
					vectorOfInts[j] = uint64_t((toPack[j].a[the_index].ConvertToInt()));
				} else {
					vectorOfInts[j] = uint64_t((toPack[j].a[the_index].ConvertToInt()));
				}
			}

			Plaintext plaintext;
			batch_encoder.encode(vectorOfInts, plaintext);
		
			if(i == 0){
				evaluator.multiply_plain(switchingKey[l], plaintext, output[l]); // times s[i]
			}
			else{
				Ciphertext temp;
				evaluator.multiply_plain(switchingKey[l], plaintext, temp);
				evaluator.add_inplace(output[l], temp);
			}
			// rotate one slot at a time
			evaluator.rotate_rows_inplace(switchingKey[l], 1, gal_keys);
		}
	}

	for(int i = 0; i < param.ell; i++){
		vector<uint64_t> vectorOfInts(toPack.size());
		for(size_t j = 0; j < toPack.size(); j++){
			vectorOfInts[j] = uint64_t((toPack[j].b[i].ConvertToInt() - param.q / 4) % param.q);
		}
		Plaintext plaintext;

		batch_encoder.encode(vectorOfInts, plaintext);
		evaluator.negate_inplace(output[i]);
		evaluator.add_plain_inplace(output[i], plaintext);
		evaluator.mod_switch_to_next_inplace(output[i]); 
	}
	MemoryManager::SwitchProfile(std::move(old_prof));
}

void computeBplusASPVWOptimizedWithFixedGroupClue(vector<Ciphertext>& output, const vector<vector<int>>& toPack, vector<Ciphertext>& switchingKey,
												  const GaloisKeys& gal_keys, const SEALContext& context, const PVWParam& param,
												  const int partialSize = partial_size_glb) {
	MemoryPoolHandle my_pool = MemoryPoolHandle::New(true);
	auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));

	int tempn_secret, tempn_shared, secret_sk_size = param.n, shared_sk_size = partialSize;
	for(tempn_secret = 1; tempn_secret < secret_sk_size; tempn_secret*=2){}
	for(tempn_shared = 1; tempn_shared < shared_sk_size; tempn_shared*=2){}

	Evaluator evaluator(context);
	BatchEncoder batch_encoder(context);
	size_t slot_count = batch_encoder.slot_count();
	if(toPack.size() > slot_count){
		cerr << "Please pack at most " << slot_count << " PVW ciphertexts at one time." << endl;
		return;
	}

	chrono::high_resolution_clock::time_point time_start, time_end;
	uint64_t ntt_total = 0;
	Ciphertext ntt_sk;

	vector<uint64_t> vectorOfInts(toPack.size());
	for (int i = 0; i < tempn_secret; i++) {
		for (int l = 0; l < param.ell; l++) {
			evaluator.transform_to_ntt(switchingKey[l], ntt_sk);
			for (int j = 0; j < (int) toPack.size(); j++) {
				int the_index = (i + j) % tempn_secret;
				if (the_index >= secret_sk_size) {
					vectorOfInts[j] = 0;
				} else {
					vectorOfInts[j] = uint64_t((toPack[j][the_index]));
				}
			}

			Plaintext plaintext;
			batch_encoder.encode(vectorOfInts, plaintext);
			time_start = chrono::high_resolution_clock::now();
			evaluator.transform_to_ntt_inplace(plaintext, ntt_sk.parms_id());
			time_end = chrono::high_resolution_clock::now();
			ntt_total += chrono::duration_cast<chrono::microseconds>(time_end - time_start).count();

			if (i == 0) {
				evaluator.multiply_plain(ntt_sk, plaintext, output[l]);
			}
			else {
				Ciphertext temp;
				evaluator.multiply_plain(ntt_sk, plaintext, temp);
				evaluator.add_inplace(output[l], temp);
			}
			// rotate one slot at a time
			evaluator.rotate_rows_inplace(switchingKey[l], 1, gal_keys);
		}
	}

	Ciphertext ntt_shared;
	for (int i = 0; i < tempn_shared; i++) {
		evaluator.transform_to_ntt(switchingKey[switchingKey.size() - 1], ntt_shared);
		for (int l = 0; l < param.ell; l++) {
			for (int j = 0; j < (int) toPack.size(); j++) {
				int the_index = (i + j) % tempn_shared;
				if (the_index >= shared_sk_size) {
					vectorOfInts[j] = 0;
				} else {// load extended_A part
					the_index += param.n + l * partialSize;
					vectorOfInts[j] = uint64_t((toPack[j][the_index]));
				}
			}

			Plaintext plaintext;
			batch_encoder.encode(vectorOfInts, plaintext);
			time_start = chrono::high_resolution_clock::now();
			evaluator.transform_to_ntt_inplace(plaintext, ntt_shared.parms_id());
			time_end = chrono::high_resolution_clock::now();
			ntt_total += chrono::duration_cast<chrono::microseconds>(time_end - time_start).count();
		
			Ciphertext temp;
			evaluator.multiply_plain(ntt_shared, plaintext, temp);
			evaluator.add_inplace(output[l], temp);
		}
		evaluator.rotate_rows_inplace(switchingKey[switchingKey.size() - 1], 1, gal_keys);
	}

	for (int e = 0; e < param.ell; e++) {
		evaluator.transform_from_ntt_inplace(output[e]);
	}

	for(int i = 0; i < param.ell; i++){
		vector<uint64_t> vectorOfInts(toPack.size());
		for(size_t j = 0; j < toPack.size(); j++){
			vectorOfInts[j] = ((uint64_t)toPack[j][param.n + param.ell * partialSize + i] - (uint64_t)(param.q / 4)) % param.q;
		}
		Plaintext plaintext;
		batch_encoder.encode(vectorOfInts, plaintext);
		evaluator.negate_inplace(output[i]);
		evaluator.add_plain_inplace(output[i], plaintext);
		evaluator.mod_switch_to_next_inplace(output[i]); 
	}
	MemoryManager::SwitchProfile(std::move(old_prof));

	cout << "ntt transform for vector total: " << ntt_total << " us.\n";
}


inline void calUptoDegreeK(vector<Ciphertext>& output, const Ciphertext& input, const int DegreeK, const RelinKeys &relin_keys,
						   const SEALContext& context) {
	vector<int> calculated(DegreeK, 0);
	Evaluator evaluator(context);
	output[0] = input;
	calculated[0] = 1; // degree 1, x
	Ciphertext res, base;
	vector<int> numMod(DegreeK, 0);

	for(int i = DegreeK; i > 0; i--){
		if(calculated[i-1] == 0){
			auto toCalculate = i;
			int resdeg = 0;
			int basedeg = 1;
			base = input;
			while(toCalculate > 0){
				if(toCalculate & 1){
					toCalculate -= 1;
					resdeg += basedeg;
					if(calculated[resdeg-1] != 0){
						res = output[resdeg - 1];
					} else {
						if(resdeg == basedeg){
							res = base; // should've never be used as base should have made calculated[basedeg-1]
						} else {
							numMod[resdeg-1] = numMod[basedeg-1];

							evaluator.mod_switch_to_inplace(res, base.parms_id()); // match modulus
							evaluator.multiply_inplace(res, base);
							evaluator.relinearize_inplace(res, relin_keys);
							while(numMod[resdeg-1] < (ceil(log2(resdeg))/2)){
								evaluator.mod_switch_to_next_inplace(res);
								numMod[resdeg-1]+=1;
							}
						}
						output[resdeg-1] = res;
						calculated[resdeg-1] += 1;
					}
				} else {
					toCalculate /= 2;
					basedeg *= 2;
					if(calculated[basedeg-1] != 0){
						base = output[basedeg - 1];
					} else {
						numMod[basedeg-1] = numMod[basedeg/2-1];
						evaluator.square_inplace(base);
						evaluator.relinearize_inplace(base, relin_keys);
						while(numMod[basedeg-1] < (ceil(log2(basedeg))/2)){
								evaluator.mod_switch_to_next_inplace(base);
								numMod[basedeg-1]+=1;
							}
						output[basedeg-1] = base;
						calculated[basedeg-1] += 1;
					}
				}
			}
		}
	}

	for(size_t i = 0; i < output.size()-1; i++){
		evaluator.mod_switch_to_inplace(output[i], output[output.size()-1].parms_id()); // match modulus
	}
	return;
}

// Use Paterson-Stockmeyer to perform the range check function
// The implementaion of this function is more hard-coded
// This is because it usess > 500 local BFV ciphertexts
// SEAL library does not free memory naturally
// Therefore, it is taking more memory than needed, and therefore
// the memory grows very fast.
// To avoid using too much RAM,
// we here have to manually create memory pools and free them
// Note that we create memory pools at different places
// Intuitively: let's say we have 128 20-level ciphertexts
// We mod them down to 3-levels, but for SEAL memory pool
// it's still taking 128 20-level ciphertexts memory
// To regain the use of those memory
// we create a memory pool and free the previous ones
// and move those 3-level ciphertexts to the new memory pool
// This is not an ideal solution
// There might be better ways to resolve this problem
inline
void RangeCheck_PatersonStockmeyer(Ciphertext& ciphertext, const Ciphertext& input, int modulus, const size_t& degree,
								const RelinKeys &relin_keys, const SEALContext& context){
	MemoryPoolHandle my_pool_larger = MemoryPoolHandle::New(true);
	auto old_prof_larger = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool_larger)));

	Evaluator evaluator(context);
	BatchEncoder batch_encoder(context);
	vector<Ciphertext> kCTs(256);
	vector<Ciphertext> temp;
	{
		MemoryPoolHandle my_pool = MemoryPoolHandle::New(true); // manually creating memory pools and desctruct them to avoid using too much memory
		auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));
		vector<Ciphertext> temp(128);
		{
			MemoryPoolHandle my_pool2 = MemoryPoolHandle::New(true);
			for(int i = 0; i < 64; i++){
				temp.push_back(Ciphertext(my_pool2));
			}
			{
				MemoryPoolHandle my_pool3 = MemoryPoolHandle::New(true);
				for(int i = 0; i < 64; i++){
					temp.push_back(Ciphertext(my_pool3));
				}
				calUptoDegreeK(temp, input, 256, relin_keys, context);
				for(size_t j = 0; j < temp.size()-1; j++){ // match to one level left, the one level left is for plaintext multiplication noise
					for(int i = 0; i < 3; i++){
						evaluator.mod_switch_to_next_inplace(temp[j]);
					}
				}
				for(int i = 255; i > 255-32-32; i--){
					kCTs[i] = temp[i];
					temp[i].release();
				}
			}
			for(int i = 255-32-32; i > 255-32-32-32-32; i--){
				kCTs[i] = temp[i];
				temp[i].release();
			}
		}
		for(int i = 0; i < 128; i++){
			kCTs[i] = temp[i];
			temp[i].release();
		}
		MemoryManager::SwitchProfile(std::move(old_prof));
	}
	vector<Ciphertext> kToMCTs(256);
	calUptoDegreeK(kToMCTs, kCTs[kCTs.size()-1], 256, relin_keys, context);
	for(int i = 0; i < 3; i++){
		evaluator.mod_switch_to_next_inplace(kCTs[kCTs.size()-1]);
	}

	for(int i = 0; i < 256; i++){
		Ciphertext levelSum;
		bool flag = false;
		for(int j = 0; j < 256; j++){
			if(rangeCheckIndices[i*256+j] != 0){
				vector<uint64_t> intInd(degree, rangeCheckIndices[i*256+j]);
				Plaintext plainInd;
				batch_encoder.encode(intInd, plainInd);
				if (!flag){
					evaluator.multiply_plain(kCTs[j], plainInd, levelSum);
					flag = true;
				} else {
					Ciphertext tmp;
					evaluator.multiply_plain(kCTs[j], plainInd, tmp);
					evaluator.add_inplace(levelSum, tmp);
				}
			}
		}
		evaluator.mod_switch_to_inplace(levelSum, kToMCTs[i].parms_id()); // mod down the plaintext multiplication noise
		if(i == 0){
			ciphertext = levelSum;
		} else {
			evaluator.multiply_inplace(levelSum, kToMCTs[i - 1]);
			evaluator.relinearize_inplace(levelSum, relin_keys);
			evaluator.add_inplace(ciphertext, levelSum);
		}
	}
	vector<uint64_t> intInd(degree, 1); 
	Plaintext plainInd;
	Ciphertext tmep;
	batch_encoder.encode(intInd, plainInd);
	evaluator.negate_inplace(ciphertext);
	evaluator.add_plain_inplace(ciphertext, plainInd);
	tmep.release();
	for(int i = 0; i < 256; i++){
		kCTs[i].release();
		kToMCTs[i].release();
	}
	MemoryManager::SwitchProfile(std::move(old_prof_larger));
}

// check in range
// if within [-range, range -1], returns 0, and returns random number in p o/w
void newRangeCheckPVW(vector<Ciphertext>& output, const int& range, const RelinKeys &relin_keys,\
						const size_t& degree, const SEALContext& context, const PVWParam& param, const int upperbound = 64){ // we do one level of recursion, so no more than 4096 elements
	Evaluator evaluator(context);
	BatchEncoder batch_encoder(context);

	vector<Ciphertext> res(param.ell);

	for(int j = 0; j < param.ell; j++){
		{
			MemoryPoolHandle my_pool_larger = MemoryPoolHandle::New(true);
			auto old_prof_larger = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool_larger)));
			auto tmp1 = output[j];
			// first use range check to obtain 0 and 1
			RangeCheck_PatersonStockmeyer(res[j], tmp1, 65537, degree, relin_keys, context);
			tmp1.release();
		}
	}
	// Multiply them to reduce the false positive rate
	EvalMultMany_inpace(res, relin_keys, context);
	output = res;
}



////////////////////////////////////////////////////// FOR OMR Optimization with RLWE clues /////////////////////////////////////////////

// compute b - aSK with packed swk but also only requires one rot key
void computeBplusAS_OPVW(vector<Ciphertext>& output, const vector<OPVWCiphertext>& toPack, vector<Ciphertext>& switchingKey,
						 const GaloisKeys& gal_keys, const SEALContext& context, const OPVWParam& param, bool default_param_set = true) {
	MemoryPoolHandle my_pool = MemoryPoolHandle::New(true);
	auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));

	int tempn, sk_size = param.n;
	for(tempn = 1; tempn < sk_size; tempn*=2){}

	// chrono::high_resolution_clock::time_point time_start, time_end;
	// int tt = 0;

	Evaluator evaluator(context);
	BatchEncoder batch_encoder(context);
	size_t slot_count = batch_encoder.slot_count();
	if(toPack.size() > slot_count){
		cerr << "Please pack at most " << slot_count << " PVW ciphertexts at one time." << endl;
		return;
	}

	for(int i = 0; i < tempn; i++){
		for(int l = 0; l < param.ell; l++){
			vector<uint64_t> vectorOfInts(toPack.size());
			for(int j = 0; j < (int)toPack.size(); j++){
				int the_index = (i + j) % tempn;
				if(the_index >= sk_size) {
					vectorOfInts[j] = 0;
				} else {
					int ring_ind = (the_index <= l) ? (l - the_index) : (sk_size - the_index + l);
					uint64_t tmp = uint64_t((toPack[j].a[ring_ind].ConvertToInt()));
					vectorOfInts[j] = the_index <= l ? tmp : bfv_Q - tmp;
				}
			}

			Plaintext plaintext;
			batch_encoder.encode(vectorOfInts, plaintext);
			evaluator.transform_to_ntt_inplace(plaintext, switchingKey[i].parms_id());
		
			if(i == 0){
				evaluator.multiply_plain(switchingKey[i], plaintext, output[l]); // times s[i]
			}
			else{
				Ciphertext temp;
				evaluator.multiply_plain(switchingKey[i], plaintext, temp);
				evaluator.add_inplace(output[l], temp);
			}
		}
	}

	for (int i = 0; i < (int) output.size(); i++) {
		evaluator.transform_from_ntt_inplace(output[i]);
	}

	for(int i = 0; i < param.ell; i++){
		vector<uint64_t> vectorOfInts(toPack.size());
		for(size_t j = 0; j < toPack.size(); j++){
			vectorOfInts[j] = toPack[j].b[i].ConvertToInt();
		}

		Plaintext plaintext;
		batch_encoder.encode(vectorOfInts, plaintext);
		evaluator.negate_inplace(output[i]);
		evaluator.add_plain_inplace(output[i], plaintext);
		if (default_param_set) {
			evaluator.mod_switch_to_next_inplace(output[i]);
		}
	}
	MemoryManager::SwitchProfile(std::move(old_prof));
}


inline void calUptoDegreeK_bigPrime(vector<Ciphertext>& output, const Ciphertext& input, const int DegreeK, const RelinKeys &relin_keys,
									const SEALContext& context, map<int, bool>& modDownIndices, const bool skip_odd=false) {
	vector<int> calculated(DegreeK, 0);
	Evaluator evaluator(context);
	output[0] = input;
	calculated[0] = 1; // degree 1, x
	Ciphertext res, base;
	vector<int> numMod(DegreeK, 0);

	for(int i = DegreeK; i > 0; i--){
		if (skip_odd && i % 2 == 1) { // 0 is for degree 1, 1 is for degree 2, skip all 2k+1 degree
			calculated[i-1] = 1;
			output[i-1] = input;
		} else if(calculated[i-1] == 0){
			auto toCalculate = i;
			int resdeg = 0;
			int basedeg = 1;
			base = input;
			while(toCalculate > 0){
				if(toCalculate & 1){
					toCalculate -= 1;
					resdeg += basedeg;
					if(calculated[resdeg-1] != 0){
						res = output[resdeg - 1];
					} else {
						if(resdeg == basedeg){
							res = base; // should've never be used as base should have made calculated[basedeg-1]
						} else {
							numMod[resdeg-1] = numMod[basedeg-1];

							evaluator.mod_switch_to_inplace(res, base.parms_id()); // match modulus
							evaluator.multiply_inplace(res, base);
							evaluator.relinearize_inplace(res, relin_keys);
							if(modDownIndices.count(resdeg) && !modDownIndices[resdeg]) {
								modDownIndices[resdeg] = true;
								evaluator.mod_switch_to_next_inplace(res);
								numMod[resdeg-1]+=1;
							}
						}
						output[resdeg-1] = res;
						calculated[resdeg-1] += 1;
					}
				} else {
					toCalculate /= 2;
					basedeg *= 2;
					if(calculated[basedeg-1] != 0){
						base = output[basedeg - 1];
					} else {
						numMod[basedeg-1] = numMod[basedeg/2-1];
						evaluator.square_inplace(base);
						evaluator.relinearize_inplace(base, relin_keys);
						while(modDownIndices.count(basedeg) && !modDownIndices[basedeg]) {
							modDownIndices[basedeg] = true;
							evaluator.mod_switch_to_next_inplace(base);
							numMod[basedeg-1]+=1;
						}
						output[basedeg-1] = base;
						calculated[basedeg-1] += 1;
					}
				}
			}
		}
	}

	for(size_t i = 0; i < output.size()-1; i++){
		evaluator.mod_switch_to_inplace(output[i], output[output.size()-1].parms_id()); // match modulus
	}
	return;
}

Ciphertext calculateDegree(const SEALContext& context, const RelinKeys &relin_keys, Ciphertext& input, map<int, bool> modDownIndices, int degree) {
	Evaluator evaluator(context);

	vector<Ciphertext> output(degree);
	output[0] = input;
	vector<int> calculated(degree, 0), numMod(degree, 0);
	calculated[0] = 1;

	Ciphertext res, base;

	auto toCalculate = degree;
	int resdeg = 0;
	int basedeg = 1;
	base = input;
	while(toCalculate > 0){
		if(toCalculate & 1){
			toCalculate -= 1;
			resdeg += basedeg;
			if(calculated[resdeg-1] != 0){
				res = output[resdeg - 1];
			} else {
				if(resdeg == basedeg){
					res = base; // should've never be used as base should have made calculated[basedeg-1]
				} else {
					numMod[resdeg-1] = numMod[basedeg-1];

					evaluator.mod_switch_to_inplace(res, base.parms_id()); // match modulus
					evaluator.multiply_inplace(res, base);
					evaluator.relinearize_inplace(res, relin_keys);
					if(modDownIndices.count(resdeg) && !modDownIndices[resdeg]) {
						modDownIndices[resdeg] = true;
						evaluator.mod_switch_to_next_inplace(res);
						numMod[resdeg-1]+=1;
					}
				}
				output[resdeg-1] = res;
				calculated[resdeg-1] += 1;
			}
		} else {
			toCalculate /= 2;
			basedeg *= 2;
			if(calculated[basedeg-1] != 0){
				base = output[basedeg - 1];
			} else {
				numMod[basedeg-1] = numMod[basedeg/2-1];
				evaluator.square_inplace(base);
				evaluator.relinearize_inplace(base, relin_keys);
				while(modDownIndices.count(basedeg) && !modDownIndices[basedeg]) {
					modDownIndices[basedeg] = true;
					evaluator.mod_switch_to_next_inplace(base);
					numMod[basedeg-1]+=1;
				}
				output[basedeg-1] = base;
				calculated[basedeg-1] += 1;
			}
		}
	}

	return output[output.size()-1];
}


Ciphertext raisePowerToPrime(const SEALContext& context, const RelinKeys &relin_keys, Ciphertext& input, map<int, bool> modDownIndices_1,
							 map<int, bool> modDownIndices_2, int degree_1, int degree_2, int prime = 65537) {

	Ciphertext tmp = calculateDegree(context, relin_keys, input, modDownIndices_1, degree_1);
	tmp = calculateDegree(context, relin_keys, tmp, modDownIndices_2, degree_2);

	return tmp;
}


// get the x^2 as input
void FastRangeCheck_Random(SecretKey& sk, Ciphertext& output, const Ciphertext& input, int degree, const RelinKeys &relin_keys,
						   const SEALContext& context, const vector<uint64_t>& rangeCheckIndices, const int firstLevel,
						   const int secondLevel, map<int, bool>& firstLevelMod, map<int, bool>& secondLevelMod,
						   bool default_param_set = true, const int range_check_range = range_check_r) {
	MemoryPoolHandle my_pool_larger = MemoryPoolHandle::New(true);
	auto old_prof_larger = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool_larger)));

	Evaluator evaluator(context);
	BatchEncoder batch_encoder(context);
	Decryptor decryptor(context, sk);

	Plaintext plainInd;
	plainInd.resize(degree);
	plainInd.parms_id() = parms_id_zero;
	for (int i = 0; i < (int) degree; i++) {
		plainInd.data()[i] = 0;
	}

	if (default_param_set) {
		vector<Ciphertext> terms(range_check_range);
		for (int i = 0; i < (int) terms.size(); i++) {
			terms[i] = input;
		}

		// get all (x-xi) terms
		for (int i = 1; i < range_check_range; i++) {
			plainInd.data()[0] = i*i;
			evaluator.negate_inplace(terms[i]);
			evaluator.add_plain_inplace(terms[i], plainInd);
		}

		EvalMultMany_inpace_modImprove(terms, relin_keys, context, sk);
		output = terms[0];

		for(int i = 0; i < (int) terms.size(); i++){
			terms[i].release();
		}
	} else {
		vector<Ciphertext> kCTs(firstLevel), kToMCTs(secondLevel);
		calUptoDegreeK_bigPrime(kCTs, input, firstLevel, relin_keys, context, firstLevelMod, true);
		/* cout << "   Noise after first level: " << decryptor.invariant_noise_budget(kCTs[kCTs.size()-1]) << " bits\n"; */
		calUptoDegreeK_bigPrime(kToMCTs, kCTs[kCTs.size()-1], secondLevel, relin_keys, context, secondLevelMod, false);
		/* cout << "   Noise after second level: " << decryptor.invariant_noise_budget(kToMCTs[kToMCTs.size()-1]) << " bits\n"; */

		Ciphertext temp_relin(context);

		for(int i = 0; i < secondLevel; i++) {
			Ciphertext levelSum;
			bool flag = false;
			for(int j = 0; j < firstLevel; j++) {
				if(rangeCheckIndices[i*firstLevel+j] != 0) {
					plainInd.data()[0] = rangeCheckIndices[i*firstLevel+j];
					if (!flag) {
						evaluator.multiply_plain(kCTs[j], plainInd, levelSum);
						flag = true;
					} else {
						Ciphertext tmp;
						evaluator.multiply_plain(kCTs[j], plainInd, tmp);
						evaluator.add_inplace(levelSum, tmp);
					}
				}
			}
			evaluator.mod_switch_to_inplace(levelSum, kToMCTs[i].parms_id()); // mod down the plaintext multiplication noise
			if(i == 0) {
				output = levelSum;
			} else if (i == 1) { // initialize for temp_relin, which is of ct size = 3
				evaluator.multiply(levelSum, kToMCTs[i - 1], temp_relin);
			} else {
				evaluator.multiply_inplace(levelSum, kToMCTs[i - 1]);
				evaluator.add_inplace(temp_relin, levelSum);
			}
		}

		for(int i = 0; i < firstLevel; i++){
			kCTs[i].release();
		}
		for(int i = 0; i < secondLevel; i++){
			kToMCTs[i].release();
		}

		evaluator.relinearize_inplace(temp_relin, relin_keys);
		evaluator.add_inplace(output, temp_relin);
		temp_relin.release();
	}

	MemoryManager::SwitchProfile(std::move(old_prof_larger));
}


Ciphertext rangeCheck_OPVW(SecretKey& sk, vector<Ciphertext>& output, const RelinKeys &relin_keys, const size_t& degree, 
					 const SEALContext& context, const OPVWParam& param, bool default_param_set = true){
	BatchEncoder batch_encoder(context);
	Evaluator evaluator(context);
	Decryptor decryptor(context, sk);

	vector<Ciphertext> res(param.ell);

	vector<uint64_t> intInd(degree, 1);
	Plaintext pl;
	batch_encoder.encode(intInd, pl);

	map<int, bool> raise_mod = {{4, false}, {16, false}, {64, false}, {256, false}};

	chrono::high_resolution_clock::time_point s,e, s1, e1;
	s = chrono::high_resolution_clock::now();

	int range_time = 0, raise_time = 0;

	for(int j = 0; j < param.ell; j++){
		{
			MemoryPoolHandle my_pool_larger = MemoryPoolHandle::New(true);
			auto old_prof_larger = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool_larger)));
			if (default_param_set) {
				evaluator.multiply_inplace(output[j], output[j]);
				evaluator.relinearize_inplace(output[j], relin_keys);
			}
			// first use range check to obtain 0 and 1
			map<int, bool> level_mod_1 = {{4, false}, {16, false}, {64, false}};
			map<int, bool> level_mod_2 = {{2, false}, {8, false}, {32, false}, {128, false}};
			if (!default_param_set) {
				level_mod_1 = {{2, false}, {8, false}, {32, false}};
				level_mod_2 = {{2, false}, {8, false}, {32, false}, {128, false}};
			}

			// Plaintext pp;
			// vector<uint64_t> tt(degree);
			// decryptor.decrypt(output[j], pp);
			// batch_encoder.decode(pp, tt);
			// cout << "============================= check before\n" << tt << endl;

			s1 = chrono::high_resolution_clock::now();
			FastRangeCheck_Random(sk, res[j], output[j], degree, relin_keys, context, rangeCheckIndices_opt_B,
								  100, 240, level_mod_1, level_mod_2, default_param_set);
			e1 = chrono::high_resolution_clock::now();
			range_time += chrono::duration_cast<chrono::microseconds>(e1 - s1).count();

			/* cout << "** Noise after net rangecheck: " << decryptor.invariant_noise_budget(res[j]) << endl; */

			if (default_param_set) {
				s1 = chrono::high_resolution_clock::now();
				Ciphertext tmp = raisePowerToPrime(context, relin_keys, res[j], raise_mod, raise_mod, 256, 256, param.q);
				e1 = chrono::high_resolution_clock::now();
				raise_time += chrono::duration_cast<chrono::microseconds>(e1 - s1).count();

				evaluator.negate_inplace(tmp);
				evaluator.add_plain_inplace(tmp, pl);
				res[j] = tmp;
			} else {
				evaluator.negate_inplace(res[j]);
				evaluator.add_plain_inplace(res[j], pl);
			}
		}
	}
	// Multiply them to reduce the false positive rate
	EvalMultMany_inpace(res, relin_keys, context);
	e = chrono::high_resolution_clock::now();
	/* cout << "   rangeCheck_OPVW time: " << chrono::duration_cast<chrono::microseconds>(e - s).count() << endl; */
	/* cout << "       range time: " << range_time << endl; */
	/* cout << "       raise time: " << raise_time << endl; */

	/* cout << "** Noise after rangecheck before mod: " << decryptor.invariant_noise_budget(res[0]) << endl; */
	evaluator.mod_switch_to_next_inplace(res[0]);
	/* cout << "** Noise after rangecheck after mod: " << decryptor.invariant_noise_budget(res[0]) << endl;     */
	return res[0];
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////// FOR DOS Optimization with snake-eye resistant PKE /////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


void computeBplusAS_dos(SecretKey& sk, vector<Ciphertext>& output, const vector<srPKECiphertext>& toPack,
						vector<vector<Ciphertext>>& switchingKey, const GaloisKeys& gal_keys,
						const SEALContext& context, const srPKEParam& param) {
	MemoryPoolHandle my_pool = MemoryPoolHandle::New(true);
	auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));

	int tempn, sk_size = param.n1;
	for(tempn = 1; tempn < sk_size; tempn*=2){}

	Evaluator evaluator(context);
	BatchEncoder batch_encoder(context);
	Decryptor decryptor(context, sk);
	
	size_t slot_count = batch_encoder.slot_count();
	if(toPack.size() > slot_count){
		cerr << "Please pack at most " << slot_count << " PVW ciphertexts at one time." << endl;
		return;
	}
	chrono::high_resolution_clock::time_point time_start, time_end;
	/* uint64_t load_time = 0; */

	Plaintext ppt;
	vector<uint64_t> test(poly_modulus_degree_glb);

	for(int i = 0; i < tempn; i++){
		for(int l = 0; l < param.ell; l++){
			/* time_start = chrono::high_resolution_clock::now(); */
			/* Ciphertext sks; */
			/* loadSwitchingKey(context, sks, l*tempn + i); */
			/* /\* sks.parms_id_ = context.first_parms_id(); *\/ */

			/* /\* evaluator.transform_from_ntt_inplace(sks); *\/ */
			/* /\* decryptor.decrypt(sks, ppt); *\/ */
			/* /\* batch_encoder.decode(ppt, test); *\/ */
			/* /\* for (int i = 0; i < 10; i++) { *\/ */
			/* /\*   cout << test[i] << " "; *\/ */
			/* /\* } *\/ */
			/* /\* cout << endl; *\/ */
			/* /\* decryptor.decrypt(switchingKey[l], ppt); *\/ */
				/* /\* batch_encoder.decode(ppt, test); *\/ */
				/* /\* for (int i = 0; i < 10; i++) { *\/ */
				/* /\*   cout << test[i] << " "; *\/ */
				/* /\* } *\/ */
				/* /\* cout << endl << "*******************************************************\n"; *\/ */
			/* /\* evaluator.transform_to_ntt_inplace(sks); *\/ */

			/* time_end = chrono::high_resolution_clock::now(); */
			/* load_time += chrono::duration_cast<chrono::microseconds>(time_end - time_start).count(); */
		
			vector<uint64_t> vectorOfInts(toPack.size());
			for(int j = 0; j < (int) toPack.size(); j++){
				int the_index = (i + j) % tempn;
				if(the_index >= sk_size) {
					vectorOfInts[j] = 0;
				} else {
					vectorOfInts[j] = uint64_t((toPack[j].a[the_index].ConvertToInt()));
				}
			}

			Plaintext plaintext;
			batch_encoder.encode(vectorOfInts, plaintext);
			evaluator.transform_to_ntt_inplace(plaintext, switchingKey[l][i].parms_id());
		
			if (i == 0){
				evaluator.multiply_plain(switchingKey[l][i], plaintext, output[l]); // times s[i]
			}
			else{
				Ciphertext temp;
				evaluator.multiply_plain(switchingKey[l][i], plaintext, temp);
				evaluator.add_inplace(output[l], temp);
			}
			/* evaluator.rotate_rows_inplace(switchingKey[l], 1, gal_keys); */
		}
	}

	/* cout << "LOAD TIME: " << load_time << endl; */

	for (int i = 0; i < (int) output.size(); i++) {
	  evaluator.transform_from_ntt_inplace(output[i]);
	}

	for(int i = 0; i < param.ell; i++){
		vector<uint64_t> vectorOfInts(toPack.size());
		for(size_t j = 0; j < toPack.size(); j++){
			vectorOfInts[j] = uint64_t((toPack[j].b[i].ConvertToInt() - param.q / 4) % param.q);
		}
		Plaintext plaintext;

		batch_encoder.encode(vectorOfInts, plaintext);
		evaluator.negate_inplace(output[i]);
		evaluator.add_plain_inplace(output[i], plaintext);
	}
	MemoryManager::SwitchProfile(std::move(old_prof));
}

Ciphertext rangeCheck_dos(SecretKey& sk, vector<Ciphertext>& output, const RelinKeys &relin_keys, const size_t& degree, 
						  const SEALContext& context, const srPKEParam& param){
	BatchEncoder batch_encoder(context);
	Evaluator evaluator(context);
	Decryptor decryptor(context, sk);

	vector<Ciphertext> res(param.ell);

	vector<uint64_t> intInd(degree, 1);
	Plaintext pl;
	batch_encoder.encode(intInd, pl);

	map<int, bool> raise_mod = {{4, false}, {16, false}, {64, false}, {256, false}};

	chrono::high_resolution_clock::time_point s,e, s1, e1;
	s = chrono::high_resolution_clock::now();

	int range_time = 0, raise_time = 0;

	for(int j = 0; j < param.ell; j++){
		{
			MemoryPoolHandle my_pool_larger = MemoryPoolHandle::New(true);
			auto old_prof_larger = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool_larger)));
			evaluator.multiply_inplace(output[j], output[j]);
			evaluator.relinearize_inplace(output[j], relin_keys);
			/* evaluator.mod_switch_to_next_inplace(output[j]); */

			/* cout << "********* first multiply: " << decryptor.invariant_noise_budget(output[j]) << endl; */

			// first use range check to obtain 0 and 1
			map<int, bool> level_mod_1 = {{4, false}, {16, false}, {64, false}};
			map<int, bool> level_mod_2 = {{2, false}, {8, false}, {32, false}, {128, false}};

			s1 = chrono::high_resolution_clock::now();
			FastRangeCheck_Random(sk, res[j], output[j], degree, relin_keys, context, rangeCheckIndices_opt_B,
				  				  100, 240, level_mod_1, level_mod_2, true, range_check_r_dos);
			evaluator.mod_switch_to_next_inplace(res[j]);
			e1 = chrono::high_resolution_clock::now();
			range_time += chrono::duration_cast<chrono::microseconds>(e1 - s1).count();
		}
	}

	evaluator.add_inplace(res[0], res[1]);

	s1 = chrono::high_resolution_clock::now();
	Ciphertext tmp1 = raisePowerToPrime(context, relin_keys, res[0], raise_mod, raise_mod, 256, 256, param.q);
	Ciphertext tmp2 = raisePowerToPrime(context, relin_keys, res[2], raise_mod, raise_mod, 256, 256, param.q);
	e1 = chrono::high_resolution_clock::now();
	raise_time += chrono::duration_cast<chrono::microseconds>(e1 - s1).count();

	evaluator.negate_inplace(tmp1);
	evaluator.add_plain_inplace(tmp1, pl);
	evaluator.negate_inplace(tmp2);
	evaluator.add_plain_inplace(tmp2, pl);
	// Multiply them to reduce the false positive rate
	evaluator.multiply(tmp1, tmp2, res[0]);
	evaluator.relinearize_inplace(res[0], relin_keys);

	e = chrono::high_resolution_clock::now();
	/* cout << "   rangeCheck_OPVW time: " << chrono::duration_cast<chrono::microseconds>(e - s).count() << endl; */
	/* cout << "       range time: " << range_time << endl; */
	/* cout << "       raise time: " << raise_time << endl; */

	/* cout << "** Noise after rangecheck before mod: " << decryptor.invariant_noise_budget(res[0]) << endl; */
	evaluator.mod_switch_to_next_inplace(res[0]);
	/* cout << "** Noise after rangecheck after mod: " << decryptor.invariant_noise_budget(res[0]) << endl;     */
	return res[0];
}
