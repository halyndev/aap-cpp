/**
 * AAP Quick Start — Agent Accountability Protocol
 * Compile: g++ -std=c++17 quickstart.cpp -lssl -lcrypto -o quickstart
 * https://aap-protocol.dev
 */
#include "../aap.hpp"
#include <iostream>

int main() {
    std::cout << "AAP — Agent Accountability Protocol\n";
    std::cout << "=====================================\n\n";

    // 1. Keypairs — human supervisor + AI agent
    auto supervisor = aap::KeyPair::generate();
    auto agent      = aap::KeyPair::generate();
    std::cout << "1. Keypairs generated (Ed25519 via OpenSSL)\n";

    // 2. Identity — signed by human supervisor
    auto identity = aap::Identity::create(
        "aap://acme/worker/deploy-bot@1.0.0",
        {"write:files", "exec:deploy"},
        agent, supervisor,
        "did:key:z6MkSupervisor"
    );
    std::cout << "2. Identity:  " << identity.id << "\n";
    std::cout << "   Scope:     [write:files, exec:deploy]\n";

    // 3. Authorization — human approves at Level 3 (Supervised)
    auto auth = aap::Authorization::create(
        identity.id,
        aap::Level::Supervised,
        {"write:files"},
        false,  // not a physical node
        supervisor,
        "did:key:z6MkSupervisor"
    );
    std::cout << "3. Auth:      level=" << auth.level_name_str
              << " valid=" << (auth.is_valid() ? "true" : "false") << "\n";

    // 4. Physical World Rule — Level 4 on robot is REJECTED
    bool blocked = false;
    try {
        aap::Authorization::create(
            "aap://factory/robot/arm@1.0.0",
            aap::Level::Autonomous,  // Level 4 — FORBIDDEN for physical
            {"move:arm"},
            true,                    // physical = true
            supervisor,
            "did:key:z6MkSupervisor"
        );
    } catch (const aap::PhysicalWorldViolation&) {
        blocked = true;
    }
    std::cout << "4. Physical World Rule blocked: " << (blocked ? "true" : "false") << "\n";

    // 5. Provenance — what did the agent produce?
    auto prov = aap::Provenance::create(
        identity.id,
        "write:file",
        "deploy instruction received",
        "deployment executed successfully",
        auth.session_id,
        agent
    );
    std::cout << "5. Provenance: " << prov.artifact_id.substr(0, 8) << "...\n";
    std::cout << "   Hash in:  " << prov.input_hash.substr(0, 20) << "...\n";
    std::cout << "   Hash out: " << prov.output_hash.substr(0, 20) << "...\n";

    // 6. Audit chain — tamper-evident record
    aap::AuditChain chain;
    chain.append(
        identity.id, "write:file",
        aap::AuditResult::Success,
        prov.artifact_id,
        agent, auth.level_val, false
    );
    auto [valid, count, broken] = chain.verify();
    std::cout << "6. Audit:     " << count << " entries, valid=" << (valid ? "true" : "false") << "\n";

    std::cout << "\n✅ Every action identified, authorized, traced, audited.\n";
    return 0;
}
