# aap.hpp — AAP C++ SDK

**Agent Accountability Protocol · Single-header C++17 · OpenSSL Ed25519**

[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![tests](https://img.shields.io/badge/tests-19%2F19-brightgreen)](https://github.com/halyndev/aap-cpp)

```bash
# One file. OpenSSL is already on your system.
curl -O https://raw.githubusercontent.com/halyndev/aap-cpp/main/aap.hpp
```

```cpp
#include "aap.hpp"

auto supervisor = aap::KeyPair::generate();
auto agent      = aap::KeyPair::generate();

auto identity = aap::Identity::create(
    "aap://factory/robot/arm@1.0.0",
    {"move:axis", "grip:actuator"},
    agent, supervisor, "did:key:z6Mk"
);

// Physical World Rule — Level 4 on physical node → PhysicalWorldViolation
try {
    aap::Authorization::create(
        identity.id, aap::Level::Autonomous,
        {"move:axis"}, true, supervisor, "did:key:z6Mk"
    );
} catch (const aap::PhysicalWorldViolation&) {
    // AAP-003: Level 4 forbidden for physical nodes.
}
```

```bash
# Compile
g++ -std=c++17 main.cpp -lssl -lcrypto -o main

# Test
g++ -std=c++17 tests/test_aap.cpp -I. -lssl -lcrypto -o test && ./test
# 19/19 passed
```

Works on Linux, macOS, Windows (MSVC), ROS2. Zero dependencies beyond OpenSSL.

**[AAP Spec](https://aap-protocol.dev) · [NRP](https://nrprotocol.dev) · [Halyn](https://halyn.dev)**

License: MIT
