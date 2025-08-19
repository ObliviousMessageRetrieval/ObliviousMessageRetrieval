// http_server.cpp  (no JSON, no base64)
// Minimal HTTP microservice bridging Rust <-> your C++ OMR/SEAL code.
// Protocol: application/octet-stream with u32 little-endian length-prefixed chunks.
// See each endpoint for exact chunk order.
#include "include/httplib.h"

#include <cstdint>
#include <cstring>
#include <iostream>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

#include "include/OMRUtil.h"
#include "include/GOMR.h"
#include "include/OMR.h"
#include "include/OMRopt.h"
#include "include/OMRdos.h"
#include "include/MRE.h"
#include "include/API.h"       // init_deaddrop, gen_clue, gen_encrypted_digest, decode_digest
#include "include/serialize.h" // your serializer/deserialize helpers

#include <seal/seal.h>

using namespace std;
using namespace seal;

// ---------- tiny binary helpers (LE) ----------
static void write_u32_le(uint32_t v, string &out)
{
    char b[4];
    b[0] = static_cast<char>(v & 0xFF);
    b[1] = static_cast<char>((v >> 8) & 0xFF);
    b[2] = static_cast<char>((v >> 16) & 0xFF);
    b[3] = static_cast<char>((v >> 24) & 0xFF);
    out.append(b, 4);
}
static bool read_u32_le(const string &in, size_t &off, uint32_t &v)
{
    if (off + 4 > in.size())
        return false;
    const unsigned char *p = reinterpret_cast<const unsigned char *>(in.data() + off);
    v = (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
    off += 4;
    return true;
}
static bool read_chunk(const string &in, size_t &off, string &chunk)
{
    uint32_t len = 0;
    if (!read_u32_le(in, off, len))
        return false;
    if (off + len > in.size())
        return false;
    chunk.assign(in.data() + off, len);
    off += len;
    return true;
}
static void write_chunk(const string &bytes, string &out)
{
    write_u32_le(static_cast<uint32_t>(bytes.size()), out);
    out.append(bytes);
}

// ---------- main ----------
int main()
{
    httplib::Server srv;

    // Health check
    srv.Get("/healthz", [](const httplib::Request &, httplib::Response &res)
            {
        static const char ok[] = "OK";
        res.set_content(ok, "text/plain"); });

    // POST /init : no body -> returns 4 chunks (sk_decode, pk_clue, pk_detect)
    srv.Post("/init", [](const httplib::Request &req, httplib::Response &res)
             {
        (void)req;
        try {
            auto [sk_decode, pk_clue, pk_detect] = init_deaddrop();

            // Serialize with your helpers
            string sk_bytes   = SerializeSecretKeyDecode(sk_decode);
            string pkc_bytes  = SerializePublicKeyClue(pk_clue);
            string pkd_bytes  = SerializePublicKeyDetect(pk_detect);

            string out;
            out.reserve(sk_bytes.size() + pkc_bytes.size() + pkd_bytes.size() + 16);
            write_chunk(sk_bytes, out);
            write_chunk(pkc_bytes, out);
            write_chunk(pkd_bytes, out);

            res.set_content(out, "application/octet-stream");
        } catch (const std::exception &e) {
            std::string msg = std::string("ERR: ") + e.what();
            res.status = 500;
            res.set_content(msg, "text/plain");
        } });

    // POST /gen_clue : body = 1 chunk (pk_clue) -> returns 1 chunk (clue)
    srv.Post("/gen_clue", [](const httplib::Request &req, httplib::Response &res)
             {
        try {
            size_t off = 0;
            string pkc_bin;
            if (!read_chunk(req.body, off, pkc_bin) || off != req.body.size()) {
                res.status = 400; res.set_content("bad body", "text/plain"); return;
            }

            auto params = srPKEParam();
            srPKEpk pk_clue = DeserializePublicKeyClue(pkc_bin, params.q);

            srPKECiphertext clue = gen_clue(pk_clue);

            string clue_bytes = SerializeClue(clue);
            string out; write_chunk(clue_bytes, out);
            res.set_content(out, "application/octet-stream");
        } catch (const std::exception &e) {
            std::string msg = std::string("ERR: ") + e.what();
            res.status = 500; res.set_content(msg, "text/plain");
        } });

    // POST /submit_clue : 
    srv.Post("/submit_clue", [](const httplib::Request &req, httplib::Response &res)
             {
        try {
            size_t off = 0;
            string clue_bin;
            string idx_bin;
            if (!read_chunk(req.body, off, clue_bin) || 
                !read_chunk(req.body, off, idx_bin)  || off != req.body.size()) {
                res.status = 400; res.set_content("bad body", "text/plain"); return;
            }

            auto params = srPKEParam();
            srPKECiphertext clue = DeserializeClue(clue_bin, params.q);
            int idx = DeserializeIndex(idx_bin);
            
            submit_clue(clue, idx);

            if (submit_clue(clue, idx)) {
                res.status = 200;
                res.set_content("OK", "text/plain");  // Success response
            } else {
                res.status = 500;
                res.set_content("Submit failed", "text/plain");  // Failure response
            }
        } catch (const std::exception &e) {
            std::string msg = std::string("ERR: ") + e.what();
            res.status = 500; res.set_content(msg, "text/plain");
        } });

    // POST /gen_encrypted_digest : body = [pk_detect] -> returns [digest]
    srv.Post("/gen_encrypted_digest", [](const httplib::Request &req, httplib::Response &res)
             {
        try {
            size_t off = 0;
            string pkd_bin, parms_bin;
            if (!read_chunk(req.body, off, pkd_bin) || off != req.body.size()) {
                res.status = 400; res.set_content("bad body", "text/plain"); return;
            }

            vector<Ciphertext> pk_detect = DeserializePublicKeyDetect(pkd_bin);
            Ciphertext digest = gen_encrypted_digest(pk_detect); 

            string digest_bytes = SerializeDigest(digest);
            string out; write_chunk(digest_bytes, out);
            res.set_content(out, "application/octet-stream");
        } catch (const std::exception &e) {
            std::string msg = std::string("ERR: ") + e.what();
            res.status = 500; res.set_content(msg, "text/plain");
        } });

    // POST /decode_digest : body = [digest][sk_decode] -> returns u32 count + count*u64 LE
    srv.Post("/decode_digest", [](const httplib::Request &req, httplib::Response &res)
             {
        try {
            size_t off = 0;
            string dig_bin, skd_bin;
            if (!read_chunk(req.body, off, dig_bin) ||
                !read_chunk(req.body, off, skd_bin) || off != req.body.size()) {
                res.status = 400; res.set_content("bad body", "text/plain"); return;
            }

            Ciphertext digest = DeserializeDigest(dig_bin);
            SecretKey  sk_decode = DeserializeSecretKeyDecode(skd_bin);

            vector<uint64_t> values = decode_digest(digest, sk_decode);

            // Return: u32 count + count*u64 LE (packed binary)
            string out;
            write_u32_le(static_cast<uint32_t>(values.size()), out);
            out.append(reinterpret_cast<const char*>(values.data()),
                       static_cast<size_t>(values.size()) * sizeof(uint64_t));
            res.set_content(out, "application/octet-stream");
        } catch (const std::exception &e) {
            std::string msg = std::string("ERR: ") + e.what();
            res.status = 500; res.set_content(msg, "text/plain");
        } });

    const char *host = "127.0.0.1";
    int port = 8080;
    std::cout << "listening on http://" << host << ":" << port << " (binary protocol)\n";
    srv.listen(host, port);
    return 0;
}
