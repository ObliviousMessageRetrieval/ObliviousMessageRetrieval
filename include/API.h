#include <iostream>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>
#include <cstring>
#include <iomanip>

#include <memory>
#include <cassert>

// --- Global, single source of truth for SEAL context ---
namespace ddctx {
    inline bool ready = false;
    inline std::shared_ptr<seal::SEALContext> g_ctx;

    // Store a single process-wide context
    inline void set(const seal::SEALContext& ctx) {
        g_ctx = std::make_shared<seal::SEALContext>(ctx); // cheap copy
        ready = true;
    }

    inline const seal::SEALContext& ctx() {
        assert(ready && "ddctx not initialized; call init_deaddrop() first");
        return *g_ctx;
    }

    // (Optional) Access to parms if you ever need them, without storing separately
    inline const seal::EncryptionParameters& parms() {
        return ddctx::ctx().key_context_data()->parms();
    }
}

// ==================================
// ======= Main API functions =======
// ==================================

// Generates sk_decode, pk_clue, pk_detect, and context for SEAL
std::tuple<SecretKey, srPKEpk, vector<Ciphertext>> init_deaddrop()
{
    // Generate first PKE pair
    auto params = srPKEParam();
    auto sk = srPKEGenerateSecretKey(params);
    auto pk_clue = srPKEGeneratePublicKey(params, sk);

    // Create clueDB
    int numOfTransactions = 32768;
    int num_of_pertinent_msgs = 0;
    int party_size_local = 1;
    vector<int> pertinentMsgIndices;
    auto expected = preparingTransactionsFormal_dos(pertinentMsgIndices, sk, pk_clue, numOfTransactions, num_of_pertinent_msgs, params, party_size_local);
    cout << "Created clue DB with dummy clues and random pertinent clues" << endl;
    cout << "Pertient message indices: " << pertinentMsgIndices << endl;

    // Configurating SEAL encryption for second PKE pair for FHE (sk_decode)
    size_t poly_modulus_degree_glb = 32768;
    size_t poly_modulus_degree = poly_modulus_degree_glb;
    int t = 65537;

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
    SecretKey sk_decode = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    // Create pk_detect
    vector<Ciphertext> pk_detect = omr_dos::generateDetectionKey(context, poly_modulus_degree, public_key,
                                                                 sk_decode, sk, params);

    ddctx::set(context);

    return std::make_tuple(sk_decode, pk_clue, pk_detect);
}

// Generates clue from pk_clue
srPKECiphertext gen_clue(const srPKEpk &pk_clue)
{
    auto params = srPKEParam();
    vector<int> zeros(params.ell, 0);
    srPKECiphertext clue;
    srPKEEncPK(clue, zeros, pk_clue, params);
    return clue;
}

// Generates encrypted digest over the whole DB
Ciphertext gen_encrypted_digest(const vector<Ciphertext> &pk_detect)
{
    auto numOfTransactions = 32768;
    auto numcores = 1;
    auto poly_modulus_degree = 32768;
    auto params = srPKEParam();
    int party_size_local = 1;

    const auto& context = ddctx::ctx();
    Evaluator evaluator(context);
    KeyGenerator keygen(context);
    BatchEncoder batch_encoder(context);

    RelinKeys relin_keys;
    keygen.create_relin_keys(relin_keys);
    GaloisKeys gal_keys;
    vector<int> stepsfirst = {1};
    keygen.create_galois_keys(stepsfirst, gal_keys);

    vector<int> counter(numcores);
    vector<vector<srPKECiphertext>> SICPVW_multicore(numcores);

    // Retrieve digest
    vector<vector<Ciphertext>> packedSICfromPhase1(numcores, vector<Ciphertext>(numOfTransactions / numcores / poly_modulus_degree));

    NTL::SetNumThreads(numcores);
    SecretKey secret_key_blank;

    int tempn;
    for (tempn = 1; tempn < params.n1; tempn *= 2)
    {
    }

    // prepare pre-processed switching key and store to disk
    vector<vector<Ciphertext>> rotated_switchingKey;

    {
        MemoryPoolHandle my_pool = MemoryPoolHandle::New();
        auto old_prof = MemoryManager::SwitchProfile(std::make_unique<MMProfFixed>(std::move(my_pool)));

        rotated_switchingKey.resize(params.ell);

        for (int l = 0; l < params.ell; l++)
        {
            rotated_switchingKey[l].resize(tempn);
            rotated_switchingKey[l][0] = pk_detect[l];

            for (int i = 1; i < tempn; i++)
            {
                evaluator.rotate_rows(rotated_switchingKey[l][i - 1], 1, gal_keys, rotated_switchingKey[l][i]);
            }
            for (int i = 0; i < tempn; i++)
            {
                evaluator.transform_to_ntt_inplace(rotated_switchingKey[l][i]);
            }
        }

        NTL_EXEC_RANGE(numcores, first, last);
        for (int i = first; i < last; i++)
        {
            counter[i] = numOfTransactions / numcores * i;

            size_t j = 0;
            while (j < static_cast<size_t>(numOfTransactions / numcores / poly_modulus_degree))
            {
                Ciphertext packedSIC_temp;

                for (int p = 0; p < party_size_local; p++)
                {
                    loadClues_dos(SICPVW_multicore[i], counter[i], counter[i] + poly_modulus_degree, params, p, party_size_local);

                    packedSIC_temp = obtainPackedSIC_dos(SICPVW_multicore[i], rotated_switchingKey, relin_keys, gal_keys,
                                                         poly_modulus_degree, context, params, poly_modulus_degree);

                    if (p == 0)
                    {
                        packedSICfromPhase1[i][j] = packedSIC_temp;
                    }
                    else
                    {
                        evaluator.add_inplace(packedSICfromPhase1[i][j], packedSIC_temp);
                    }
                }
                j++;
                counter[i] += poly_modulus_degree;
                SICPVW_multicore[i].clear();
            }
        }

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

    return res;
}

// Decodes encrypted digest using sk_decode and SEAL context
vector<uint64_t> decode_digest(const Ciphertext &encrypted_digest, const SecretKey &sk_decode)
{
    const auto& context = ddctx::ctx();
    Decryptor decryptor(context, sk_decode);
    BatchEncoder batch_encoder(context);
    // Decrypt the ciphertext
    Plaintext plaintext_digest;
    decryptor.decrypt(encrypted_digest, plaintext_digest);

    // Decode to get the raw values
    vector<uint64_t> decoded_digest;
    batch_encoder.decode(plaintext_digest, decoded_digest);

    return decoded_digest;
}

// Submits clue to index i in clueDB
bool submit_clue(const srPKECiphertext &clue, int index) {
    try {
        saveClues_dos(clue, index);
        return true;  // Success
    } catch (const std::exception &e) {
        return false;  // Failed
    }
}

// ==================================
// ======= Printing functions =======
// ==================================
void PrintSecretKeyDecode(const seal::SecretKey& sk, size_t max_to_print = 16)
{
    const auto &pt = sk.data();
    size_t count = std::min(max_to_print, pt.coeff_count());

    std::cout << "SecretKey coefficients (first " << count << "): [";
    for (size_t i = 0; i < count; ++i)
    {
        std::cout << pt[i];
        if (i + 1 != count)
            std::cout << ", ";
    }
    if (pt.coeff_count() > count)
        std::cout << ", ...";
    std::cout << "]\n";
}

void PrintPublicKeyClue(const srPKEpk &pk)
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

void PrintPublicKeyDetect(const vector<Ciphertext> &switchingKey)
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

void PrintClue(const srPKECiphertext &ct, const string &label = "CLUE")
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

void PrintDigest(const seal::Ciphertext& ct, std::size_t max_per_poly = 16)
{
    // N = poly_modulus_degree, K = # of primes in coeff_modulus
    const std::size_t N = ct.poly_modulus_degree();
    const std::size_t polys = ct.size();

    for (std::size_t p = 0; p < polys; ++p) {
        const auto* ptr = ct.data(p);          // start of this poly's data
        const std::size_t count = std::min(N, max_per_poly);

        std::cout << "poly " << p << ": [";
        for (std::size_t i = 0; i < count; ++i) {
            std::cout << ptr[i];
            if (i + 1 != count) std::cout << ", ";
        }
        if (count < N) std::cout << ", ...";
        std::cout << "]\n";
    }
}

void PrintBinary(const std::vector<uint8_t> &binary_clue)
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

void PrintDigest(const vector<uint64_t> &values, int x = 2000)
{
    cout << "First " << x << " values: ";
    for (int i = 0; i < x && i < static_cast<int>(values.size()); i++)
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

