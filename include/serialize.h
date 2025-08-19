using std::string;
using std::string_view;

// ==== helpers: write/read little-endian u32/u64 ====
inline void append_u32(string &out, uint32_t v)
{
    uint8_t b[4];
    b[0] = uint8_t(v);
    b[1] = uint8_t(v >> 8);
    b[2] = uint8_t(v >> 16);
    b[3] = uint8_t(v >> 24);
    out.append(reinterpret_cast<char *>(b), 4);
}
inline void append_u64(string &out, uint64_t v)
{
    uint8_t b[8];
    b[0] = uint8_t(v);
    b[1] = uint8_t(v >> 8);
    b[2] = uint8_t(v >> 16);
    b[3] = uint8_t(v >> 24);
    b[4] = uint8_t(v >> 32);
    b[5] = uint8_t(v >> 40);
    b[6] = uint8_t(v >> 48);
    b[7] = uint8_t(v >> 56);
    out.append(reinterpret_cast<char *>(b), 8);
}

inline uint32_t read_u32(string_view buf, size_t &off)
{
    if (off + 4 > buf.size())
        throw std::runtime_error("deserialize: short read u32");
    const uint8_t *p = reinterpret_cast<const uint8_t *>(buf.data() + off);
    off += 4;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
inline uint64_t read_u64(string_view buf, size_t &off)
{
    if (off + 8 > buf.size())
        throw std::runtime_error("deserialize: short read u64");
    const uint8_t *p = reinterpret_cast<const uint8_t *>(buf.data() + off);
    off += 8;
    return (uint64_t)p[0] | ((uint64_t)p[1] << 8) | ((uint64_t)p[2] << 16) | ((uint64_t)p[3] << 24) |
           ((uint64_t)p[4] << 32) | ((uint64_t)p[5] << 40) | ((uint64_t)p[6] << 48) | ((uint64_t)p[7] << 56);
}

// ==== NativeInteger helpers ====
// Convert NativeInteger < 2^64 to uint64_t. Assumes your modulus fits in 64 bits (usual for Native backend).
inline uint64_t to_u64(const NativeInteger &x)
{
    // Most PALISADE NativeInteger types expose ConvertToInt / ConvertToLong / ConvertToULL.
    // Use ConvertToULL if you have it; fallback to ConvertToInt for 32-bit builds.
#if defined(__GNUC__) || defined(__clang__)
    return static_cast<uint64_t>(x.ConvertToInt()); // many NativeIntegerT have ConvertToInt()
#else
    return static_cast<uint64_t>(x.ConvertToInt());
#endif
}
inline NativeInteger from_u64(uint64_t v)
{
    return NativeInteger(v);
}

// ==== NativeVector <-> bytes ====
// Serialize without modulus; caller provides modulus on decode.
inline string SerializeNativeVectorLE64(const NativeVector &nv)
{
    string out;
    const uint32_t len = static_cast<uint32_t>(nv.GetLength()); // or nv.size()
    append_u32(out, len);
    for (uint32_t i = 0; i < len; ++i)
    {
        append_u64(out, to_u64(nv[i]));
    }
    return out;
}

// Construct a NativeVector of given length and modulus, then fill coefficients.
inline NativeVector DeserializeNativeVectorLE64(string_view buf, size_t &off, const NativeInteger &modulus)
{
    uint32_t len = read_u32(buf, off);
    NativeVector nv(len, modulus); // ctor (len, modulus) exists for NativeVector backends
    for (uint32_t i = 0; i < len; ++i)
    {
        uint64_t v = read_u64(buf, off);
        nv[i] = from_u64(v);
        // ensure within modulus if needed:
        if (nv[i] >= modulus)
            nv[i] = nv[i] % modulus;
    }
    return nv;
}

// ---- srPKEpk ---- (pk_clue)
inline string SerializePublicKeyClue(const srPKEpk &pk)
{
    string out;
    append_u32(out, static_cast<uint32_t>(pk.size()));
    for (const auto &ct : pk)
    {
        string a = SerializeNativeVectorLE64(ct.a);
        string b = SerializeNativeVectorLE64(ct.b);
        out.append(a);
        out.append(b);
    }
    return out;
}

inline srPKEpk DeserializePublicKeyClue(string_view bytes, const NativeInteger &modulus)
{
    size_t off = 0;
    if (bytes.size() < 4)
        throw std::runtime_error("DeserializePublicKey: short header");
    uint32_t n = read_u32(bytes, off);
    srPKEpk pk;
    pk.reserve(n);
    for (uint32_t i = 0; i < n; ++i)
    {
        srPKECiphertext ct{
            DeserializeNativeVectorLE64(bytes, off, modulus),
            DeserializeNativeVectorLE64(bytes, off, modulus)};
        pk.emplace_back(std::move(ct));
    }
    if (off != bytes.size())
    {
        throw std::runtime_error("DeserializePublicKey: trailing bytes");
    }
    return pk;
}

// ---- srPKECiphertext ---- (clue)
inline string SerializeClue(const srPKECiphertext &ct)
{
    string out;
    out.append(SerializeNativeVectorLE64(ct.a));
    out.append(SerializeNativeVectorLE64(ct.b));
    return out;
}

inline srPKECiphertext DeserializeClue(string_view bytes, const NativeInteger &modulus)
{
    size_t off = 0;
    srPKECiphertext ct{
        DeserializeNativeVectorLE64(bytes, off, modulus),
        DeserializeNativeVectorLE64(bytes, off, modulus)};
    if (off != bytes.size())
        throw std::runtime_error("DeserializeCiphertext: trailing bytes");
    return ct;
}

// ---- vector<Ciphertext> ---- (pk_detect)
inline std::string SerializePublicKeyDetect(const std::vector<seal::Ciphertext> &cts)
{
    using namespace seal;
    std::string out;
    // count
    append_u32(out, static_cast<uint32_t>(cts.size()));

    for (const auto &ct : cts)
    {
        // ask SEAL how many bytes are needed (no compression)
        std::streamoff need = ct.save_size(seal::compr_mode_type::none);
        if (need < 0)
            throw std::runtime_error("SerializeCiphertexts: negative save_size");
        uint64_t nbytes = static_cast<uint64_t>(need);

        // write size header
        append_u64(out, nbytes);

        // write the ciphertext bytes
        size_t old_sz = out.size();
        out.resize(old_sz + static_cast<size_t>(nbytes));
        auto *dest = reinterpret_cast<seal::seal_byte *>(&out[old_sz]);
        std::streamoff written = ct.save(dest, static_cast<size_t>(nbytes), seal::compr_mode_type::none);
        if (written != static_cast<std::streamoff>(nbytes))
            throw std::runtime_error("SerializeCiphertexts: size mismatch on save()");
    }
    return out;
}

inline std::vector<seal::Ciphertext> DeserializePublicKeyDetect(std::string_view bytes)
{
    const auto& context = ddctx::ctx();
    using namespace seal;
    size_t off = 0;

    // read count
    if (bytes.size() < 4)
        throw std::runtime_error("DeserializeCiphertexts: short header");
    uint32_t count = read_u32(bytes, off);

    std::vector<Ciphertext> out;
    out.reserve(count);

    for (uint32_t i = 0; i < count; ++i)
    {
        // read byte length
        if (off + 8 > bytes.size())
            throw std::runtime_error("DeserializeCiphertexts: short size");
        uint64_t nbytes = read_u64(bytes, off);

        // bounds check
        if (off + static_cast<size_t>(nbytes) > bytes.size())
            throw std::runtime_error("DeserializeCiphertexts: truncated ciphertext payload");

        // load into a new Ciphertext and validate against context
        seal::Ciphertext ct; // or Ciphertext ct;
        const auto *src = reinterpret_cast<const seal_byte *>(bytes.data() + off);
        std::streamoff loaded = ct.load(context, src, static_cast<size_t>(nbytes));
        if (loaded != static_cast<std::streamoff>(nbytes))
            throw std::runtime_error("DeserializeCiphertexts: size mismatch on load()");

        out.emplace_back(std::move(ct));
        off += static_cast<size_t>(nbytes);
    }

    if (off != bytes.size())
        throw std::runtime_error("DeserializeCiphertexts: trailing bytes");

    return out;
}

// ---- SecretKey ---- (sk_decode)
inline std::string SerializeSecretKeyDecode(const seal::SecretKey &sk)
{
    // Ask SEAL for exact size (no compression for simplicity/determinism)
    std::streamoff need = sk.save_size(seal::compr_mode_type::none);
    if (need < 0)
        throw std::runtime_error("SerializeSealSecretKey: negative save_size");
    const auto nbytes = static_cast<size_t>(need);

    std::string out;
    out.resize(nbytes);
    auto *dest = reinterpret_cast<seal::seal_byte *>(&out[0]);

    std::streamoff written = sk.save(dest, nbytes, seal::compr_mode_type::none);
    if (written != static_cast<std::streamoff>(nbytes))
        throw std::runtime_error("SerializeSealSecretKey: size mismatch on save()");
    return out;
}

inline seal::SecretKey DeserializeSecretKeyDecode(std::string_view bytes)
{
    const auto& context = ddctx::ctx();
    seal::SecretKey sk;
    const auto *src = reinterpret_cast<const seal::seal_byte *>(bytes.data());

    std::streamoff loaded = sk.load(context, src, bytes.size());
    if (loaded != static_cast<std::streamoff>(bytes.size()))
        throw std::runtime_error("DeserializeSealSecretKey: size mismatch on load()");
    return sk;
}

// ---- Ciphertext ---- (digest)
inline std::string SerializeDigest(const seal::Ciphertext &ct)
{
    std::streamoff need = ct.save_size(seal::compr_mode_type::none);
    if (need < 0)
        throw std::runtime_error("SerializeSealCiphertext: negative save_size");
    const auto nbytes = static_cast<size_t>(need);

    std::string out;
    out.resize(nbytes);
    auto *dest = reinterpret_cast<seal::seal_byte *>(&out[0]);

    std::streamoff written = ct.save(dest, nbytes, seal::compr_mode_type::none);
    if (written != static_cast<std::streamoff>(nbytes))
        throw std::runtime_error("SerializeSealCiphertext: size mismatch on save()");
    return out;
}

inline seal::Ciphertext DeserializeDigest(std::string_view bytes)
{
    const auto& context = ddctx::ctx();
    seal::Ciphertext ct; // default-construct; load() allocates as needed
    const auto *src = reinterpret_cast<const seal::seal_byte *>(bytes.data());
    std::streamoff loaded = ct.load(context, src, bytes.size());
    if (loaded != static_cast<std::streamoff>(bytes.size()))
        throw std::runtime_error("DeserializeSealCiphertext: size mismatch on load()");
    return ct;
}

// for submit clue
int DeserializeIndex(std::string_view bytes) {
    if (bytes.size() != 4) {
        // Handle error - wrong size
        return 0;
    }
    int value;
    memcpy(&value, bytes.data(), sizeof(int));
    return value;
}