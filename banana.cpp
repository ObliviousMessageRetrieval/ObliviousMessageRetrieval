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

using namespace seal;

int main(int argc, char *argv[])
{
    auto [sk_decode, pk_clue, pk_detect] = init_deaddrop();
    cout << "All keys generated, clueDB created" << endl;
    // auto clue = gen_clue(pk_clue);

    auto pkd = SerializePublicKeyDetect(pk_detect);
    auto pks = DeserializePublicKeyDetect(pkd);

    auto digest = gen_encrypted_digest(pks); // main line

    auto d = SerializeDigest(digest);
    auto dd = DeserializeDigest(d);
    auto skd = SerializeSecretKeyDecode(sk_decode);
    auto skdd = DeserializeSecretKeyDecode(skd);

    auto decoded_digest = decode_digest(dd, skdd); // main line
    print_nonzero_indices(decoded_digest);
} 