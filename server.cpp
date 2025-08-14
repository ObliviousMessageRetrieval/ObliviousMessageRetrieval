#include "include/OMRUtil.h"
#include "include/GOMR.h"
#include "include/OMR.h"
#include "include/OMRopt.h"
#include "include/OMRdos.h"
#include "include/MRE.h"
#include <openssl/aes.h>
#include <string.h>
#include "include/API.h"

using namespace seal;

int main(int argc, char *argv[])
{
    auto params = srPKEParam();
    auto [sk, pk] = gen_OMR_PKE();
    auto [pk_detect, sk2, context] = gen_pk_detect(sk);
    cout << "All keys generated" << endl;
    auto encrypted_digest = gen_encrypted_digest(sk, pk, pk_detect, sk2, context);
    cout << "Generated encrypted digest!" << endl;
    auto decoded_digest = decode_digest(encrypted_digest, sk2, context);
    cout << "Generated decoded and decrypted digest!" << endl;
    print_nonzero_indices(decoded_digest);
}
