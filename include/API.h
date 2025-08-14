#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#include <iomanip>

// ==================================
// ======= Main API functions =======
// ==================================

// Generates sk1 and pk_clue
std::pair<srPKEsk, srPKEpk> gen_OMR_PKE()
{
    auto params = srPKEParam();
    auto sk = srPKEGenerateSecretKey(params);
    auto pk = srPKEGeneratePublicKey(params, sk);
    return std::make_pair(sk, pk);
}

// Generates clue from pk_clue
srPKECiphertext gen_clue(const srPKEpk &pk)
{
    auto params = srPKEParam();
    vector<int> zeros(params.ell, 0);
    srPKECiphertext clue;
    srPKEEncPK(clue, zeros, pk, params);
    return clue;
}

// Generates pk_detect and sk_decode from sk1
std::tuple<vector<Ciphertext>, SecretKey, SEALContext> gen_pk_detect(const srPKEsk &sk)
{
    // Global variables
    size_t poly_modulus_degree_glb = 32768;
    size_t poly_modulus_degree = poly_modulus_degree_glb;
    int t = 65537;

    auto params = srPKEParam();

    // Configurating SEAL encryption
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(poly_modulus_degree);
    auto coeff_modulus = CoeffModulus::Create(poly_modulus_degree, {40, 60, 60, 60, 60,
                                                                    60, 60, 60, 60,
                                                                    60, 60, 60, 60,
                                                                    60, 60, 30, 60});
    parms.set_coeff_modulus(coeff_modulus);
    parms.set_plain_modulus(t);
    prng_seed_type seed;
    for (auto &i : seed)
    {
        i = random_uint64();
    }
    auto rng = make_shared<Blake2xbPRNGFactory>(Blake2xbPRNGFactory(seed));
    parms.set_random_generator(rng);

    SEALContext context(parms, true, sec_level_type::none);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    // Create switchingKey (pk_detect)
    vector<Ciphertext> switchingKey = omr_dos::generateDetectionKey(context, poly_modulus_degree, public_key,
                                                                    secret_key, sk, params);

    // Create secret_key_small (sk_decode)
    // auto degree = poly_modulus_degree;

    // EncryptionParameters bfv_params_small(scheme_type::bfv);
    // bfv_params_small.set_poly_modulus_degree(degree);
    // auto coeff_modulus_small = CoeffModulus::Create(degree, {28, 60});
    // bfv_params_small.set_coeff_modulus(coeff_modulus_small);
    // bfv_params_small.set_plain_modulus(t);

    // bfv_params_small.set_random_generator(rng);
    // SEALContext seal_context_small(bfv_params_small, true, sec_level_type::none);
    // KeyGenerator keygen_small(seal_context_small);

    // SecretKey secret_key_small = keygen_small.secret_key();

    // uint64_t small_p = 268369920;
    // uint64_t large_p = 1099510054912;

    // inverse_ntt_negacyclic_harvey(secret_key.data().data(), context.key_context_data()->small_ntt_tables()[0]);
    // inverse_ntt_negacyclic_harvey(secret_key_small.data().data(), seal_context_small.key_context_data()->small_ntt_tables()[0]);
    // for (int i = 0; i < (int)degree; i++)
    // {
    //     secret_key_small.data()[i] = (secret_key.data()[i] == large_p) ? small_p : secret_key.data()[i];
    // }
    // seal::util::RNSIter new_key_rns_small1(secret_key_small.data().data(), degree);
    // ntt_negacyclic_harvey(new_key_rns_small1, coeff_modulus_small.size(), seal_context_small.key_context_data()->small_ntt_tables());

    // Return just the base keys - server will handle rotation
    return std::make_tuple(switchingKey, secret_key, context);
}

void print_digest(const vector<uint64_t> &values, int x = 2000)
{
    cout << "First " << x << " values: ";
    for (int i = 0; i < x && i < values.size(); i++)
    {
        cout << values[i] << " ";
    }
    cout << endl;
}

void print_nonzero_indices(const std::vector<uint64_t> &values)
{
    std::cout << "Indices with non-zero values: ";
    for (std::size_t i = 0; i < values.size(); i++)
    {
        if (values[i] != 0)
        {
            std::cout << i << " ";
        }
    }
    std::cout << std::endl;
}

// Generates encrypted digest over the whole DB
Ciphertext gen_encrypted_digest(srPKEsk &sk, srPKEpk &pk, const vector<Ciphertext> &switchingKey, SecretKey &secret_key, const SEALContext &context)
{
    // Global variables
    auto numOfTransactions = 32768;
    auto numcores = 1;
    auto poly_modulus_degree = 32768;
    auto params = srPKEParam();
    int t = 65537;

    Evaluator evaluator(context);
    KeyGenerator keygen(context, secret_key);
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    vector<int> stepsfirst = {1};
    keygen.create_galois_keys(stepsfirst, gal_keys);

    vector<int> counter(numcores);
    vector<vector<srPKECiphertext>> SICPVW_multicore(numcores);
    cout << "1" << endl;

    // Set up clues and payloads
    int party_size_local = 1;
    int half_party_size = ceil(((double)party_size_local) / 2.0);
    int payload_size = 306;
    createDatabase(numOfTransactions, payload_size * 2);
    cout << "created dummy payloads" << endl;

    vector<int> pertinentMsgIndices;
    auto expected = preparingTransactionsFormal_dos(pertinentMsgIndices, sk, pk, numOfTransactions, num_of_pertinent_msgs_glb, params, party_size_local);
    cout << "created dummy and pertinent clues" << endl;
    cout << "Pertient message indices: " << pertinentMsgIndices << endl;

    // Retrieve digest
    vector<vector<Ciphertext>> packedSICfromPhase1(numcores, vector<Ciphertext>(numOfTransactions / numcores / poly_modulus_degree));
    // Assume numOfTransactions/numcores/poly_modulus_degree is integer, pad if needed

    NTL::SetNumThreads(numcores);
    SecretKey secret_key_blank;

    chrono::high_resolution_clock::time_point time_start, time_end, s, e;
    chrono::microseconds time_diff;

    Plaintext pl;
    vector<uint64_t> tm(poly_modulus_degree);

    int tempn;
    for (tempn = 1; tempn < params.n1; tempn *= 2)
    {
    }
    cout << "2" << endl;

    // prepare pre-processed switching key and store to disk
    vector<vector<Ciphertext>> rotated_switchingKey;

    {
        MemoryPoolHandle my_pool = MemoryPoolHandle::New();
        auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));

        rotated_switchingKey.resize(params.ell);

        s = chrono::high_resolution_clock::now();
        cout << "Begin creating rotating switching key from pk_detect" << endl;
        /* Ciphertext curr, next; */
        for (int l = 0; l < params.ell; l++)
        {
            rotated_switchingKey[l].resize(tempn);
            rotated_switchingKey[l][0] = switchingKey[l];

            for (int i = 1; i < tempn; i++)
            {
                evaluator.rotate_rows(rotated_switchingKey[l][i - 1], 1, gal_keys, rotated_switchingKey[l][i]);
            }
            for (int i = 0; i < tempn; i++)
            {
                evaluator.transform_to_ntt_inplace(rotated_switchingKey[l][i]);
            }
        }
        e = chrono::high_resolution_clock::now();
        cout << "Prepare switching key time: " << chrono::duration_cast<chrono::microseconds>(e - s).count() << endl;

        time_start = chrono::high_resolution_clock::now();
        cout << "3" << endl;

        NTL_EXEC_RANGE(numcores, first, last);
        chrono::high_resolution_clock::time_point s1, e1;
        uint64_t t11 = 0, t22 = 0, bb_to_pv = 0;
        for (int i = first; i < last; i++)
        {
            counter[i] = numOfTransactions / numcores * i;

            size_t j = 0;
            while (j < numOfTransactions / numcores / poly_modulus_degree)
            {
                /* if(!i) cout << "Phase 1, Core " << i << ", Batch " << j << endl; */

                Ciphertext packedSIC_temp;
                s1 = chrono::high_resolution_clock::now();
                for (int p = 0; p < party_size_local; p++)
                {

                    s = chrono::high_resolution_clock::now();
                    loadClues_dos(SICPVW_multicore[i], counter[i], counter[i] + poly_modulus_degree, params, p, party_size_local);
                    // loadClues_dos(SICPVW_multicore[i], counter[i], counter[i] + poly_modulus_degree, params);
                    e = chrono::high_resolution_clock::now();
                    t11 += chrono::duration_cast<chrono::microseconds>(e - s).count();

                    s = chrono::high_resolution_clock::now();
                    packedSIC_temp = obtainPackedSIC_dos(secret_key, SICPVW_multicore[i], rotated_switchingKey, relin_keys, gal_keys,
                                                         poly_modulus_degree, context, params, poly_modulus_degree);
                    cout << "** Noise after phase 1: " << decryptor.invariant_noise_budget(packedSIC_temp) << endl;

                    decryptor.decrypt(packedSIC_temp, pl);
                    batch_encoder.decode(pl, tm);

                    size_t hits = 0;
                    for (auto v : tm)
                        if (v % t)
                            ++hits;
                    std::cerr << "[dbg] hits in this party/batch = " << hits << "\n";

                    // cout << "SIC after rangeCheck: ------------------------------ \n";
                    // for (int c = 0; c < (int)100; c++)
                    // {
                    //     cout << tm[c] << " ";
                    // }
                    // cout << endl;

                    if (p == 0)
                    {
                        packedSICfromPhase1[i][j] = packedSIC_temp;
                    }
                    else
                    {
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
                // cout << "BB to PV time: " << chrono::duration_cast<chrono::microseconds>(e1 - s1).count() << endl;
            }
        }

        cout << "ClueToPackedPV time: " << bb_to_pv << " us.\n";

        NTL_EXEC_RANGE_END;

        for (int l = 0; l < params.ell; l++)
        {
            for (int i = 0; i < tempn; i++)
            {
                rotated_switchingKey[l][i].release();
            }
        }

        MemoryManager::SwitchProfile(std::move(old_prof));
    }
    cout << "4" << endl;

    // Compression to get a single ciphertext as output
    int determinCounter = 0;
    Ciphertext res;
    for (size_t i = 0; i < packedSICfromPhase1.size(); i++)
    {
        for (size_t j = 0; j < packedSICfromPhase1[i].size(); j++)
        {
            Plaintext plain_matrix;
            vector<uint64_t> pod_matrix(poly_modulus_degree, 1ULL << determinCounter);
            batch_encoder.encode(pod_matrix, plain_matrix);
            if ((i == 0) && (j == 0))
            {
                evaluator.multiply_plain(packedSICfromPhase1[i][j], plain_matrix, res);
            }
            else
            {
                evaluator.multiply_plain_inplace(packedSICfromPhase1[i][j], plain_matrix);
                evaluator.add_inplace(res, packedSICfromPhase1[i][j]);
            }
            determinCounter++;
        }
    }
    // // Decrypt the ciphertext
    // Plaintext plaintext_digest;
    // decryptor.decrypt(res, plaintext_digest);

    // // Decode to get the raw values
    // vector<uint64_t> decoded_digest;
    // batch_encoder.decode(plaintext_digest, decoded_digest);

    // print_digest(decoded_digest);
    // print_nonzero_indices(decoded_digest);
    // print_nonzero_indices_logical(decoded_digest, /*t=*/65537, /*n=*/poly_modulus_degree);

    // return decoded_digest;
    return res;
}

vector<uint64_t> decode_digest(const Ciphertext &encrypted_digest, const SecretKey &secret_key, const SEALContext &context)
{
    Decryptor decryptor(context, secret_key);
    BatchEncoder batch_encoder(context);
    // Decrypt the ciphertext
    Plaintext plaintext_digest;
    decryptor.decrypt(encrypted_digest, plaintext_digest);

    // Decode to get the raw values
    vector<uint64_t> decoded_digest;
    batch_encoder.decode(plaintext_digest, decoded_digest);

    return decoded_digest;
}

// ===========================================================
// ======= Serialization and deserialization functions =======
// ===========================================================
std::vector<uint8_t> serialize_clue_binary(const srPKECiphertext &clue)
{
    std::vector<uint8_t> buffer;

    // Helper lambda to append uint64_t to buffer in little-endian
    auto append_uint64 = [&buffer](uint64_t value)
    {
        for (int i = 0; i < 8; i++)
        {
            buffer.push_back((value >> (i * 8)) & 0xFF);
        }
    };

    // Serialize vector a
    size_t len_a = clue.a.GetLength();
    uint64_t mod_a = clue.a.GetModulus().ConvertToInt();

    append_uint64(len_a);
    append_uint64(mod_a);

    for (size_t i = 0; i < len_a; i++)
    {
        append_uint64(clue.a[i].ConvertToInt());
    }

    // Serialize vector b
    size_t len_b = clue.b.GetLength();
    uint64_t mod_b = clue.b.GetModulus().ConvertToInt();

    append_uint64(len_b);
    append_uint64(mod_b);

    for (size_t i = 0; i < len_b; i++)
    {
        append_uint64(clue.b[i].ConvertToInt());
    }

    return buffer;
}

srPKECiphertext deserialize_clue_binary(const std::vector<uint8_t> &buffer)
{
    if (buffer.size() < 32)
    { // Minimum: 4 * 8 bytes for lengths and moduli
        throw std::runtime_error("Buffer too small for srPKECiphertext deserialization");
    }

    size_t offset = 0;

    // Helper lambda to read uint64_t from buffer in little-endian
    auto read_uint64 = [&buffer, &offset]() -> uint64_t
    {
        if (offset + 8 > buffer.size())
        {
            throw std::runtime_error("Buffer underflow during deserialization");
        }
        uint64_t value = 0;
        for (int i = 0; i < 8; i++)
        {
            value |= (static_cast<uint64_t>(buffer[offset + i]) << (i * 8));
        }
        offset += 8;
        return value;
    };

    srPKECiphertext clue;

    // Deserialize vector a
    uint64_t len_a = read_uint64();
    uint64_t mod_a = read_uint64();

    NativeInteger modulus_a(mod_a);
    clue.a = NativeVector(len_a, modulus_a);

    for (size_t i = 0; i < len_a; i++)
    {
        uint64_t elem = read_uint64();
        clue.a[i] = NativeInteger(elem);
    }

    // Deserialize vector b
    uint64_t len_b = read_uint64();
    uint64_t mod_b = read_uint64();

    NativeInteger modulus_b(mod_b);
    clue.b = NativeVector(len_b, modulus_b);

    for (size_t i = 0; i < len_b; i++)
    {
        uint64_t elem = read_uint64();
        clue.b[i] = NativeInteger(elem);
    }

    return clue;
}

// ==================================
// ======= Printing functions =======
// ==================================
void print_srPKECiphertext(const srPKECiphertext &ct, const string &label = "CLUE")
{
    cout << "=== " << label << " ===" << endl;

    // Print vector 'a'
    cout << "Vector a (size " << ct.a.GetLength() << "): ";
    for (int i = 0; i < min(15, (int)ct.a.GetLength()); i++)
    {
        cout << ct.a[i] << " ";
    }
    if (ct.a.GetLength() > 15)
        cout << "... (+" << (ct.a.GetLength() - 15) << " more)";
    cout << endl;

    // Print vector 'b'
    cout << "Vector b (size " << ct.b.GetLength() << "): ";
    for (int i = 0; i < min(15, (int)ct.b.GetLength()); i++)
    {
        cout << ct.b[i] << " ";
    }
    if (ct.b.GetLength() > 15)
        cout << "... (+" << (ct.b.GetLength() - 15) << " more)";
    cout << endl;
    cout << endl;
}

void print_secret_key(const srPKEsk &sk)
{
    cout << "=== SECRET KEY ===" << endl;
    cout << "Number of vectors: " << sk.size() << endl;
    for (int i = 0; i < sk.size(); i++)
    {
        cout << "Vector " << i << " (size " << sk[i].GetLength() << "): ";
        // Print first 10 elements to avoid spam
        for (int j = 0; j < min(10, (int)sk[i].GetLength()); j++)
        {
            cout << sk[i][j] << " ";
        }
        if (sk[i].GetLength() > 10)
            cout << "...";
        cout << endl;
    }
    cout << endl;
}

void print_public_key(const srPKEpk &pk)
{
    cout << "=== PUBLIC KEY ===" << endl;
    cout << "Number of ciphertexts: " << pk.size() << endl;
    for (int i = 0; i < min(3, (int)pk.size()); i++)
    { // Just print first 3
        cout << "Ciphertext " << i << ":" << endl;
        cout << "  a (size " << pk[i].a.GetLength() << "): ";
        for (int j = 0; j < min(10, (int)pk[i].a.GetLength()); j++)
        {
            cout << pk[i].a[j] << " ";
        }
        if (pk[i].a.GetLength() > 10)
            cout << "...";
        cout << endl;

        cout << "  b (size " << pk[i].b.GetLength() << "): ";
        for (int j = 0; j < min(10, (int)pk[i].b.GetLength()); j++)
        {
            cout << pk[i].b[j] << " ";
        }
        if (pk[i].b.GetLength() > 10)
            cout << "...";
        cout << endl;
    }
    if (pk.size() > 3)
        cout << "... (" << (pk.size() - 3) << " more ciphertexts)" << endl;
    cout << endl;
}

void print_binary(const std::vector<uint8_t> &binary_clue)
{
    std::cout << "Binary[" << binary_clue.size() << "]: ";
    for (size_t i = 0; i < std::min(size_t(32), binary_clue.size()); i++)
    {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(binary_clue[i]);
    }
    if (binary_clue.size() > 32)
    {
        std::cout << "...";
    }
    std::cout << std::dec << std::endl;
}

void print_switching_key(const vector<Ciphertext> &switchingKey)
{
    cout << "\n=== Switching Key Information ===" << endl;
    cout << "Number of switching keys: " << switchingKey.size() << endl;

    for (size_t i = 0; i < switchingKey.size(); i++)
    {
        const Ciphertext &ct = switchingKey[i];

        cout << "\nSwitching Key [" << i << "]:" << endl;
        cout << "  - Size (polynomials): " << ct.size() << endl;
        cout << "  - Polynomial modulus degree: " << ct.poly_modulus_degree() << endl;
        cout << "  - Coefficient modulus size: " << ct.coeff_modulus_size() << endl;

        // Calculate memory size
        size_t memory_bytes = ct.size() * ct.poly_modulus_degree() * ct.coeff_modulus_size() * sizeof(uint64_t);
        cout << "  - Memory size: " << memory_bytes / (1024.0 * 1024.0) << " MB" << endl;

        // Print first few coefficients for visualization
        if (ct.size() > 0 && ct.data(0) != nullptr)
        {
            cout << "  - First 10 coefficients: ";
            for (int j = 0; j < min(10, (int)ct.poly_modulus_degree()); j++)
            {
                cout << ct.data(0)[j] << " ";
            }
            cout << "..." << endl;
        }
    }

    // Calculate total size
    size_t total_bytes = 0;
    for (const auto &ct : switchingKey)
    {
        total_bytes += ct.size() * ct.poly_modulus_degree() * ct.coeff_modulus_size() * sizeof(uint64_t);
    }

    cout << "\nTotal size: " << total_bytes / (1024.0 * 1024.0) << " MB" << endl;
    cout << "================================\n"
         << endl;
}

void print_secret_key_small(const SecretKey &secret_key_small)
{
    const auto &sk_data = secret_key_small.data();
    size_t coeff_count = sk_data.coeff_count();

    cout << "\n[SecretKey] " << coeff_count << " coefficients" << endl;
    cout << "First 30: ";
    for (size_t i = 0; i < 30 && i < coeff_count; i++)
    {
        cout << sk_data[i] << " ";
    }
    cout << "\nLast 10: ";
    for (size_t i = coeff_count - 10; i < coeff_count; i++)
    {
        cout << sk_data[i] << " ";
    }
    cout << endl;
}

size_t get_memory_usage_mb()
{
    std::ifstream file("/proc/self/status");
    std::string line;
    while (std::getline(file, line))
    {
        if (line.substr(0, 6) == "VmRSS:")
        {
            std::istringstream iss(line);
            std::string label, value, unit;
            iss >> label >> value >> unit;
            return std::stoul(value) / 1024;
        }
    }
    return 0;
}