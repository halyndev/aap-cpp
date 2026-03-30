/**
 * aap.hpp — Agent Accountability Protocol
 * Single-header C++17 implementation.
 *
 * https://aap-protocol.dev
 * License: MIT
 *
 * Requirements:
 *   OpenSSL 1.1+ or 3.x   (available on all Linux, macOS, Windows)
 *
 * Compile:
 *   g++ -std=c++17 main.cpp -lssl -lcrypto -o main
 *   cl  /std:c++17 main.cpp openssl\lib\libssl.lib openssl\lib\libcrypto.lib
 *
 * Quick start:
 *   auto supervisor = aap::KeyPair::generate();
 *   auto agent      = aap::KeyPair::generate();
 *   auto identity   = aap::Identity::create("aap://acme/worker/bot@1.0.0",
 *                         {"write:files"}, agent, supervisor, "did:key:z6Mk...");
 */
#pragma once

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <optional>
#include <regex>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

namespace aap {

// ─────────────────────────────────────────────────────────────────────────────
// Error types
// ─────────────────────────────────────────────────────────────────────────────

struct ValidationError : std::runtime_error {
    std::string field;
    explicit ValidationError(const std::string& field, const std::string& msg)
        : std::runtime_error("AAP-001: validation error on '" + field + "': " + msg)
        , field(field) {}
};

struct SignatureError : std::runtime_error {
    explicit SignatureError(const std::string& msg)
        : std::runtime_error("AAP-002: signature error: " + msg) {}
};

struct PhysicalWorldViolation : std::runtime_error {
    explicit PhysicalWorldViolation(const std::string& agent_id)
        : std::runtime_error(
            "AAP-003: Physical World Rule: Autonomous (Level 4) is forbidden "
            "for physical agent '" + agent_id + "'. "
            "Maximum level is Supervised (Level 3). This rule is not configurable.") {}
};

struct RevocationError : std::runtime_error {
    explicit RevocationError(const std::string& id)
        : std::runtime_error("AAP-005: '" + id + "' has been revoked") {}
};

struct ChainError : std::runtime_error {
    explicit ChainError(const std::string& entry_id)
        : std::runtime_error("AAP-006: audit chain broken at entry '" + entry_id + "'") {}
};

// ─────────────────────────────────────────────────────────────────────────────
// Internal utilities
// ─────────────────────────────────────────────────────────────────────────────

namespace detail {

// Base64 encoding/decoding (RFC 4648)
static const std::string B64_CHARS =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

inline std::string b64_encode(const std::vector<uint8_t>& data) {
    std::string out;
    int val = 0, valb = -6;
    for (uint8_t c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out += B64_CHARS[(val >> valb) & 0x3F];
            valb -= 6;
        }
    }
    if (valb > -6) out += B64_CHARS[((val << 8) >> (valb + 8)) & 0x3F];
    while (out.size() % 4) out += '=';
    return out;
}

inline std::vector<uint8_t> b64_decode(const std::string& s) {
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[B64_CHARS[i]] = i;
    std::vector<uint8_t> out;
    int val = 0, valb = -8;
    for (char c : s) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back((val >> valb) & 0xFF);
            valb -= 8;
        }
    }
    return out;
}

// Current UTC timestamp as ISO 8601 string
inline std::string utc_now() {
    auto now = std::chrono::system_clock::now();
    auto t = std::chrono::system_clock::to_time_t(now);
    std::ostringstream ss;
    ss << std::put_time(std::gmtime(&t), "%Y-%m-%dT%H:%M:%SZ");
    return ss.str();
}

// Generate a UUID v4
inline std::string uuid_v4() {
    uint8_t bytes[16];
    RAND_bytes(bytes, sizeof(bytes));
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    std::ostringstream ss;
    for (int i = 0; i < 16; i++) {
        if (i == 4 || i == 6 || i == 8 || i == 10) ss << '-';
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)bytes[i];
    }
    return ss.str();
}

// SHA-256 → "sha256:<hex>"
inline std::string sha256_of(const std::string& data) {
    uint8_t hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const uint8_t*>(data.data()), data.size(), hash);
    std::ostringstream ss;
    ss << "sha256:";
    for (auto b : hash) ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
    return ss.str();
}

// Minimal JSON builder — no external dependency
inline std::string json_str(const std::string& s) {
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += "\\\"";
        else if (c == '\\') out += "\\\\";
        else if (c == '\n') out += "\\n";
        else out += c;
    }
    return out + "\"";
}

inline std::string json_array(const std::vector<std::string>& v) {
    std::string out = "[";
    for (size_t i = 0; i < v.size(); i++) {
        if (i) out += ",";
        out += json_str(v[i]);
    }
    return out + "]";
}

} // namespace detail

// ─────────────────────────────────────────────────────────────────────────────
// KeyPair — Ed25519 via OpenSSL
// ─────────────────────────────────────────────────────────────────────────────

class KeyPair {
public:
    /// Generate a new random Ed25519 keypair.
    static KeyPair generate() {
        EVP_PKEY* key = nullptr;
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
        if (!ctx) throw SignatureError("failed to create key context");
        EVP_PKEY_keygen_init(ctx);
        EVP_PKEY_keygen(ctx, &key);
        EVP_PKEY_CTX_free(ctx);
        return KeyPair(key);
    }

    /// Return the public key in AAP wire format: "ed25519:<base64>".
    std::string public_key_b64() const {
        size_t len = 32;
        std::vector<uint8_t> buf(len);
        EVP_PKEY_get_raw_public_key(key_, buf.data(), &len);
        return "ed25519:" + detail::b64_encode(buf);
    }

    /// Sign data, returning the signature in AAP wire format: "ed25519:<base64>".
    std::string sign(const std::string& data) const {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        EVP_DigestSignInit(ctx, nullptr, nullptr, nullptr, key_);
        size_t sig_len = 64;
        std::vector<uint8_t> sig(sig_len);
        EVP_DigestSign(ctx, sig.data(), &sig_len,
            reinterpret_cast<const uint8_t*>(data.data()), data.size());
        EVP_MD_CTX_free(ctx);
        return "ed25519:" + detail::b64_encode(sig);
    }

    ~KeyPair() { if (key_) EVP_PKEY_free(key_); }
    KeyPair(KeyPair&& o) noexcept : key_(o.key_) { o.key_ = nullptr; }
    KeyPair(const KeyPair&) = delete;
    KeyPair& operator=(const KeyPair&) = delete;

private:
    explicit KeyPair(EVP_PKEY* k) : key_(k) {}
    EVP_PKEY* key_;
};

/// Verify an Ed25519 AAP signature. Throws SignatureError on failure.
inline void verify_signature(const std::string& public_key_b64,
                              const std::string& data,
                              const std::string& signature_b64) {
    auto pub_strip = public_key_b64.substr(public_key_b64.find(':') + 1);
    auto sig_strip = signature_b64.substr(signature_b64.find(':') + 1);
    auto pub_bytes = detail::b64_decode(pub_strip);
    auto sig_bytes = detail::b64_decode(sig_strip);

    EVP_PKEY* key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr,
        pub_bytes.data(), pub_bytes.size());
    if (!key) throw SignatureError("invalid public key");

    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(ctx, nullptr, nullptr, nullptr, key);
    int ok = EVP_DigestVerify(ctx, sig_bytes.data(), sig_bytes.size(),
        reinterpret_cast<const uint8_t*>(data.data()), data.size());
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(key);

    if (ok != 1) throw SignatureError("signature mismatch");
}

// ─────────────────────────────────────────────────────────────────────────────
// Identity
// ─────────────────────────────────────────────────────────────────────────────

class Identity {
public:
    std::string aap_version = "0.1";
    std::string id;
    std::string public_key;
    std::string parent;
    std::vector<std::string> scope;
    std::string issued_at;
    std::optional<std::string> expires_at;
    bool revoked = false;
    std::unordered_map<std::string, std::string> metadata;
    std::string signature;

    /// Create and sign a new Identity.
    /// parent_kp is the human supervisor — they sign the agent's identity.
    static Identity create(
        const std::string& id,
        const std::vector<std::string>& scope,
        const KeyPair& agent_kp,
        const KeyPair& parent_kp,
        const std::string& parent_did)
    {
        static const std::regex id_re(
            R"(^aap://[a-z0-9\-\.]+/[a-z0-9\-]+/[a-z0-9\-\.]+@\d+\.\d+\.\d+$)");
        static const std::regex scope_re(R"(^[a-z]+:[a-z0-9_\-\*]+$)");

        if (!std::regex_match(id, id_re))
            throw ValidationError("id",
                "invalid format: '" + id + "' — expected aap://org/type/name@semver");
        if (scope.empty())
            throw ValidationError("scope", "must contain at least one item");
        for (auto& s : scope)
            if (!std::regex_match(s, scope_re))
                throw ValidationError("scope",
                    "invalid item '" + s + "' — expected verb:resource");

        Identity ident;
        ident.id         = id;
        ident.public_key = agent_kp.public_key_b64();
        ident.parent     = parent_did;
        ident.scope      = scope;
        ident.issued_at  = detail::utc_now();

        std::string canonical = ident.to_json_signable();
        ident.signature = parent_kp.sign(canonical);
        return ident;
    }

    /// Check if action is in this identity's scope.
    bool allows_action(const std::string& action) const {
        auto colon = action.find(':');
        std::string verb     = (colon != std::string::npos) ? action.substr(0, colon) : action;
        std::string resource = (colon != std::string::npos) ? action.substr(colon + 1) : "";
        for (auto& s : scope) {
            auto sc = s.find(':');
            std::string sv = (sc != std::string::npos) ? s.substr(0, sc) : s;
            std::string sr = (sc != std::string::npos) ? s.substr(sc + 1) : "";
            if (sv == verb && (sr == "*" || sr == resource)) return true;
        }
        return false;
    }

    bool is_expired() const {
        return false; // simplified — implement with chrono if needed
    }

    /// Verify signature against the parent's public key.
    void verify(const std::string& parent_public_key_b64) const {
        if (revoked) throw RevocationError(id);
        verify_signature(parent_public_key_b64, to_json_signable(), signature);
    }

    std::string to_json() const {
        std::ostringstream j;
        j << "{"
          << "\"aap_version\":" << detail::json_str(aap_version) << ","
          << "\"id\":"          << detail::json_str(id) << ","
          << "\"public_key\":"  << detail::json_str(public_key) << ","
          << "\"parent\":"      << detail::json_str(parent) << ","
          << "\"scope\":"       << detail::json_array(scope) << ","
          << "\"issued_at\":"   << detail::json_str(issued_at) << ","
          << "\"revoked\":"     << (revoked ? "true" : "false") << ","
          << "\"signature\":"   << detail::json_str(signature)
          << "}";
        return j.str();
    }

private:
    std::string to_json_signable() const {
        // Same as to_json but without "signature" field
        std::ostringstream j;
        j << "{"
          << "\"aap_version\":" << detail::json_str(aap_version) << ","
          << "\"id\":"          << detail::json_str(id) << ","
          << "\"public_key\":"  << detail::json_str(public_key) << ","
          << "\"parent\":"      << detail::json_str(parent) << ","
          << "\"scope\":"       << detail::json_array(scope) << ","
          << "\"issued_at\":"   << detail::json_str(issued_at) << ","
          << "\"revoked\":"     << (revoked ? "true" : "false")
          << "}";
        return j.str();
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Authorization
// ─────────────────────────────────────────────────────────────────────────────

enum class Level : uint8_t {
    Observe    = 0,
    Suggest    = 1,
    Assisted   = 2,
    Supervised = 3,
    Autonomous = 4,
};

inline const char* level_name(Level l) {
    switch (l) {
        case Level::Observe:    return "observe";
        case Level::Suggest:    return "suggest";
        case Level::Assisted:   return "assisted";
        case Level::Supervised: return "supervised";
        case Level::Autonomous: return "autonomous";
    }
    return "unknown";
}

class Authorization {
public:
    std::string aap_version = "0.1";
    std::string agent_id;
    uint8_t     level_val;
    std::string level_name_str;
    std::vector<std::string> scope;
    bool        physical;
    std::string granted_by;
    std::string granted_at;
    std::optional<std::string> expires_at;
    std::string session_id;
    std::string signature;

    /// Create and sign a new Authorization.
    /// PHYSICAL WORLD RULE: throws PhysicalWorldViolation if physical + Level::Autonomous.
    static Authorization create(
        const std::string& agent_id,
        Level level,
        const std::vector<std::string>& scope,
        bool physical,
        const KeyPair& supervisor_kp,
        const std::string& supervisor_did)
    {
        // PHYSICAL WORLD RULE — enforced here. Cannot be bypassed.
        if (physical && level > Level::Supervised)
            throw PhysicalWorldViolation(agent_id);

        Authorization auth;
        auth.agent_id      = agent_id;
        auth.level_val     = static_cast<uint8_t>(level);
        auth.level_name_str = level_name(level);
        auth.scope         = scope;
        auth.physical      = physical;
        auth.granted_by    = supervisor_did;
        auth.granted_at    = detail::utc_now();
        auth.session_id    = detail::uuid_v4();

        auth.signature = supervisor_kp.sign(auth.to_json_signable());
        return auth;
    }

    void revoke() { revoked_ = true; }
    bool is_revoked() const { return revoked_; }
    bool is_valid()   const { return !revoked_; }

    void check() const {
        if (revoked_) throw RevocationError(session_id);
    }

    std::string to_json() const {
        std::ostringstream j;
        j << "{"
          << "\"aap_version\":" << detail::json_str(aap_version) << ","
          << "\"agent_id\":"    << detail::json_str(agent_id) << ","
          << "\"level\":"       << (int)level_val << ","
          << "\"level_name\":"  << detail::json_str(level_name_str) << ","
          << "\"scope\":"       << detail::json_array(scope) << ","
          << "\"physical\":"    << (physical ? "true" : "false") << ","
          << "\"granted_by\":"  << detail::json_str(granted_by) << ","
          << "\"granted_at\":"  << detail::json_str(granted_at) << ","
          << "\"session_id\":"  << detail::json_str(session_id) << ","
          << "\"signature\":"   << detail::json_str(signature)
          << "}";
        return j.str();
    }

private:
    bool revoked_ = false;

    std::string to_json_signable() const {
        std::ostringstream j;
        j << "{"
          << "\"aap_version\":" << detail::json_str(aap_version) << ","
          << "\"agent_id\":"    << detail::json_str(agent_id) << ","
          << "\"level\":"       << (int)level_val << ","
          << "\"level_name\":"  << detail::json_str(level_name_str) << ","
          << "\"scope\":"       << detail::json_array(scope) << ","
          << "\"physical\":"    << (physical ? "true" : "false") << ","
          << "\"granted_by\":"  << detail::json_str(granted_by) << ","
          << "\"granted_at\":"  << detail::json_str(granted_at) << ","
          << "\"session_id\":"  << detail::json_str(session_id)
          << "}";
        return j.str();
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Provenance
// ─────────────────────────────────────────────────────────────────────────────

class Provenance {
public:
    std::string aap_version = "0.1";
    std::string artifact_id;
    std::string agent_id;
    std::string action;
    std::string input_hash;
    std::string output_hash;
    std::string authorization_id;
    std::string timestamp;
    std::optional<std::string> target;
    std::string signature;

    /// Create and sign provenance for an agent-produced artifact.
    static Provenance create(
        const std::string& agent_id,
        const std::string& action,
        const std::string& input_data,
        const std::string& output_data,
        const std::string& authorization_id,
        const KeyPair& agent_kp)
    {
        Provenance p;
        p.artifact_id      = detail::uuid_v4();
        p.agent_id         = agent_id;
        p.action           = action;
        p.input_hash       = detail::sha256_of(input_data);
        p.output_hash      = detail::sha256_of(output_data);
        p.authorization_id = authorization_id;
        p.timestamp        = detail::utc_now();

        p.signature = agent_kp.sign(p.to_json_signable());
        return p;
    }

    std::string to_json() const {
        std::ostringstream j;
        j << "{"
          << "\"aap_version\":"      << detail::json_str(aap_version) << ","
          << "\"artifact_id\":"      << detail::json_str(artifact_id) << ","
          << "\"agent_id\":"         << detail::json_str(agent_id) << ","
          << "\"action\":"           << detail::json_str(action) << ","
          << "\"input_hash\":"       << detail::json_str(input_hash) << ","
          << "\"output_hash\":"      << detail::json_str(output_hash) << ","
          << "\"authorization_id\":" << detail::json_str(authorization_id) << ","
          << "\"timestamp\":"        << detail::json_str(timestamp) << ","
          << "\"signature\":"        << detail::json_str(signature)
          << "}";
        return j.str();
    }

private:
    std::string to_json_signable() const {
        std::ostringstream j;
        j << "{"
          << "\"aap_version\":"      << detail::json_str(aap_version) << ","
          << "\"artifact_id\":"      << detail::json_str(artifact_id) << ","
          << "\"agent_id\":"         << detail::json_str(agent_id) << ","
          << "\"action\":"           << detail::json_str(action) << ","
          << "\"input_hash\":"       << detail::json_str(input_hash) << ","
          << "\"output_hash\":"      << detail::json_str(output_hash) << ","
          << "\"authorization_id\":" << detail::json_str(authorization_id) << ","
          << "\"timestamp\":"        << detail::json_str(timestamp)
          << "}";
        return j.str();
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// AuditChain
// ─────────────────────────────────────────────────────────────────────────────

enum class AuditResult { Success, Failure, Blocked, Revoked };

inline const char* audit_result_str(AuditResult r) {
    switch (r) {
        case AuditResult::Success:  return "success";
        case AuditResult::Failure:  return "failure";
        case AuditResult::Blocked:  return "blocked";
        case AuditResult::Revoked:  return "revoked";
    }
    return "unknown";
}

struct AuditEntry {
    std::string aap_version = "0.1";
    std::string entry_id;
    std::string prev_hash;
    std::string agent_id;
    std::string action;
    std::string result;
    std::string timestamp;
    std::string provenance_id;
    uint8_t     authorization_level;
    bool        physical;
    std::string signature;

    std::string to_json() const {
        std::ostringstream j;
        j << "{"
          << "\"aap_version\":"         << detail::json_str(aap_version) << ","
          << "\"entry_id\":"            << detail::json_str(entry_id) << ","
          << "\"prev_hash\":"           << detail::json_str(prev_hash) << ","
          << "\"agent_id\":"            << detail::json_str(agent_id) << ","
          << "\"action\":"              << detail::json_str(action) << ","
          << "\"result\":"              << detail::json_str(result) << ","
          << "\"timestamp\":"           << detail::json_str(timestamp) << ","
          << "\"provenance_id\":"       << detail::json_str(provenance_id) << ","
          << "\"authorization_level\":" << (int)authorization_level << ","
          << "\"physical\":"            << (physical ? "true" : "false") << ","
          << "\"signature\":"           << detail::json_str(signature)
          << "}";
        return j.str();
    }
};

class AuditChain {
public:
    /// Append a new signed entry to the chain.
    AuditEntry& append(
        const std::string& agent_id,
        const std::string& action,
        AuditResult result,
        const std::string& provenance_id,
        const KeyPair& agent_kp,
        uint8_t authorization_level = 0,
        bool physical = false)
    {
        AuditEntry e;
        e.entry_id            = detail::uuid_v4();
        e.prev_hash           = last_hash();
        e.agent_id            = agent_id;
        e.action              = action;
        e.result              = audit_result_str(result);
        e.timestamp           = detail::utc_now();
        e.provenance_id       = provenance_id;
        e.authorization_level = authorization_level;
        e.physical            = physical;

        // Sign the entry without the signature field
        std::ostringstream signable;
        signable << "{"
            << "\"aap_version\":"         << detail::json_str(e.aap_version) << ","
            << "\"entry_id\":"            << detail::json_str(e.entry_id) << ","
            << "\"prev_hash\":"           << detail::json_str(e.prev_hash) << ","
            << "\"agent_id\":"            << detail::json_str(e.agent_id) << ","
            << "\"action\":"              << detail::json_str(e.action) << ","
            << "\"result\":"              << detail::json_str(e.result) << ","
            << "\"timestamp\":"           << detail::json_str(e.timestamp) << ","
            << "\"provenance_id\":"       << detail::json_str(e.provenance_id) << ","
            << "\"authorization_level\":" << (int)e.authorization_level << ","
            << "\"physical\":"            << (e.physical ? "true" : "false")
            << "}";
        e.signature = agent_kp.sign(signable.str());

        entries_.push_back(std::move(e));
        return entries_.back();
    }

    /// Verify chain integrity. Returns {valid, entries_checked, broken_at_id}.
    struct VerifyResult { bool valid; size_t count; std::string broken_at; };

    VerifyResult verify() const {
        std::string prev = "genesis";
        for (size_t i = 0; i < entries_.size(); i++) {
            if (entries_[i].prev_hash != prev)
                return {false, i, entries_[i].entry_id};
            prev = detail::sha256_of(entries_[i].to_json());
        }
        return {true, entries_.size(), ""};
    }

    size_t size() const { return entries_.size(); }
    bool   empty() const { return entries_.empty(); }
    const std::vector<AuditEntry>& entries() const { return entries_; }

private:
    std::vector<AuditEntry> entries_;

    std::string last_hash() const {
        if (entries_.empty()) return "genesis";
        return detail::sha256_of(entries_.back().to_json());
    }
};

} // namespace aap
