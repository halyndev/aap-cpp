#include "../aap.hpp"
#include <cassert>
#include <functional>
#include <iostream>
#include <string>

static int passed = 0, failed = 0;

void run(const std::string& name, std::function<void()> fn) {
    try {
        fn();
        std::cout << "  OK  " << name << "\n";
        ++passed;
    } catch (const std::exception& e) {
        std::cout << "  FAIL " << name << " — " << e.what() << "\n";
        ++failed;
    } catch (...) {
        std::cout << "  FAIL " << name << " — unknown exception\n";
        ++failed;
    }
}

int main() {
    std::cout << "AAP C++ Test Suite\n==================\n";

    run("identity_create", [] {
        auto sup = aap::KeyPair::generate();
        auto ag  = aap::KeyPair::generate();
        auto id  = aap::Identity::create("aap://acme/worker/bot@1.0.0", {"read:files"}, ag, sup, "did:key:z");
        assert(id.id == "aap://acme/worker/bot@1.0.0");
        assert(!id.signature.empty());
    });

    run("identity_invalid_id", [] {
        auto sup = aap::KeyPair::generate();
        auto ag  = aap::KeyPair::generate();
        try {
            aap::Identity::create("not-valid", {"read:files"}, ag, sup, "did:key:z");
            assert(false && "should have thrown");
        } catch (const aap::ValidationError&) {}
    });

    run("identity_empty_scope", [] {
        auto sup = aap::KeyPair::generate();
        auto ag  = aap::KeyPair::generate();
        try {
            aap::Identity::create("aap://x/y/z@1.0.0", {}, ag, sup, "did:key:z");
            assert(false && "should have thrown");
        } catch (const aap::ValidationError&) {}
    });

    run("identity_allows_action", [] {
        auto sup = aap::KeyPair::generate();
        auto ag  = aap::KeyPair::generate();
        auto id  = aap::Identity::create("aap://x/y/z@1.0.0", {"read:files", "write:*"}, ag, sup, "did:key:z");
        assert(id.allows_action("read:files"));
        assert(id.allows_action("write:anything"));
        assert(!id.allows_action("delete:files"));
    });

    run("identity_verify_correct_key", [] {
        auto sup = aap::KeyPair::generate();
        auto ag  = aap::KeyPair::generate();
        auto id  = aap::Identity::create("aap://x/y/z@1.0.0", {"read:files"}, ag, sup, "did:key:z");
        id.verify(sup.public_key_b64());
    });

    run("identity_verify_wrong_key", [] {
        auto sup   = aap::KeyPair::generate();
        auto ag    = aap::KeyPair::generate();
        auto wrong = aap::KeyPair::generate();
        auto id    = aap::Identity::create("aap://x/y/z@1.0.0", {"read:files"}, ag, sup, "did:key:z");
        try {
            id.verify(wrong.public_key_b64());
            assert(false && "should have thrown");
        } catch (const aap::SignatureError&) {}
    });

    run("identity_revoked_fails", [] {
        auto sup = aap::KeyPair::generate();
        auto ag  = aap::KeyPair::generate();
        auto id  = aap::Identity::create("aap://x/y/z@1.0.0", {"read:files"}, ag, sup, "did:key:z");
        id.revoked = true;
        try {
            id.verify(sup.public_key_b64());
            assert(false && "should have thrown");
        } catch (const aap::RevocationError&) {}
    });

    run("auth_valid", [] {
        auto sup  = aap::KeyPair::generate();
        auto auth = aap::Authorization::create("aap://x/y/z@1.0.0", aap::Level::Supervised, {"write:files"}, false, sup, "did:key:z");
        assert(auth.is_valid());
        assert(auth.level_name_str == "supervised");
    });

    run("physical_world_rule_blocks_autonomous", [] {
        auto sup = aap::KeyPair::generate();
        try {
            aap::Authorization::create("aap://factory/robot/arm@1.0.0", aap::Level::Autonomous, {"move:arm"}, true, sup, "did:key:z");
            assert(false && "should have thrown");
        } catch (const aap::PhysicalWorldViolation&) {}
    });

    run("physical_supervised_allowed", [] {
        auto sup  = aap::KeyPair::generate();
        auto auth = aap::Authorization::create("aap://factory/robot/arm@1.0.0", aap::Level::Supervised, {"move:arm"}, true, sup, "did:key:z");
        assert(auth.is_valid());
    });

    run("digital_autonomous_allowed", [] {
        auto sup  = aap::KeyPair::generate();
        auto auth = aap::Authorization::create("aap://x/y/z@1.0.0", aap::Level::Autonomous, {"read:files"}, false, sup, "did:key:z");
        assert(auth.is_valid());
    });

    run("auth_revoke", [] {
        auto sup  = aap::KeyPair::generate();
        auto auth = aap::Authorization::create("aap://x/y/z@1.0.0", aap::Level::Observe, {"read:files"}, false, sup, "did:key:z");
        auth.revoke();
        assert(!auth.is_valid());
        try { auth.check(); assert(false); } catch (const aap::RevocationError&) {}
    });

    run("provenance_create", [] {
        auto ag   = aap::KeyPair::generate();
        auto prov = aap::Provenance::create("aap://x/y/z@1.0.0", "write:file", "input", "output", "sess-1", ag);
        assert(!prov.artifact_id.empty());
        assert(prov.input_hash.substr(0, 7) == "sha256:");
    });

    run("provenance_same_input_same_hash", [] {
        auto ag = aap::KeyPair::generate();
        auto p1 = aap::Provenance::create("aap://x/y/z@1.0.0", "read:file", "same", "same", "s1", ag);
        auto p2 = aap::Provenance::create("aap://x/y/z@1.0.0", "read:file", "same", "same", "s2", ag);
        assert(p1.input_hash == p2.input_hash);
    });

    run("audit_empty_valid", [] {
        aap::AuditChain chain;
        auto [valid, count, broken] = chain.verify();
        assert(valid && count == 0 && broken.empty());
    });

    run("audit_append_and_verify", [] {
        auto ag = aap::KeyPair::generate();
        aap::AuditChain chain;
        chain.append("aap://x/y/z@1.0.0", "write:file", aap::AuditResult::Success, "prov-1", ag);
        auto [valid, count, broken] = chain.verify();
        assert(valid && count == 1);
    });

    run("audit_genesis_hash", [] {
        auto ag = aap::KeyPair::generate();
        aap::AuditChain chain;
        auto& e = chain.append("aap://x/y/z@1.0.0", "read:file", aap::AuditResult::Success, "prov-1", ag);
        assert(e.prev_hash == "genesis");
    });

    run("audit_five_entries", [] {
        auto ag = aap::KeyPair::generate();
        aap::AuditChain chain;
        for (int i = 0; i < 5; i++)
            chain.append("aap://x/y/z@1.0.0", "write:file", aap::AuditResult::Success, "prov", ag);
        auto [valid, count, b] = chain.verify();
        assert(valid && count == 5);
    });

    run("audit_blocked_recorded", [] {
        auto ag = aap::KeyPair::generate();
        aap::AuditChain chain;
        auto& e = chain.append("aap://factory/robot/arm@1.0.0", "move:arm",
            aap::AuditResult::Blocked, "prov-1", ag, 3, true);
        assert(e.result == "blocked" && e.physical == true);
    });

    std::cout << "\n" << passed << "/" << (passed + failed) << " passed\n";
    return failed ? 1 : 0;
}
