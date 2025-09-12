#include "include/OMRUtil.h"
#include "include/GOMR.h"
#include "include/OMR.h"
#include "include/OMRopt.h"
#include "include/OMRdos.h"
#include "include/MRE.h"
#include <openssl/aes.h>
#include <string.h>
#include "include/API.h"
#include "include/serialize.h"

#include <chrono>
#include <iostream>

using namespace seal;

int main(int argc, char *argv[])
{
    auto start = std::chrono::high_resolution_clock::now();

    start = std::chrono::high_resolution_clock::now();
    auto [sk_decode, pk_clue, pk_detect] = init_deaddrop();
    std::cout << "init_deaddrop: " 
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::high_resolution_clock::now() - start).count()
              << " ms\n";

    start = std::chrono::high_resolution_clock::now();
    auto clue = gen_clue(pk_clue);
    std::cout << "gen_clue: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::high_resolution_clock::now() - start).count()
              << " ms\n";

    start = std::chrono::high_resolution_clock::now();
    submit_clue(clue, 50000);
    std::cout << "submit_clue: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::high_resolution_clock::now() - start).count()
              << " ms\n";

    start = std::chrono::high_resolution_clock::now();
    auto digest = gen_encrypted_digest(pk_detect);
    std::cout << "gen_encrypted_digest: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::high_resolution_clock::now() - start).count()
              << " ms\n";

    start = std::chrono::high_resolution_clock::now();
    auto decoded_digest = decode_digest(digest, sk_decode);
    std::cout << "decode_digest: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::high_resolution_clock::now() - start).count()
              << " ms\n";

    start = std::chrono::high_resolution_clock::now();
    print_nonzero_indices(decoded_digest);
    std::cout << "print_nonzero_indices: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::high_resolution_clock::now() - start).count()
              << " ms\n";

    std::cout << "decoded_digest length: " << decoded_digest.size() << "\n";
}
