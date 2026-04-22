#include <gtest/gtest.h>
#include "rules_engine.h"
#include <fstream>
#include <filesystem>

static std::string write_rules(const std::string& yaml,
                                const std::filesystem::path& dir) {
    auto path = dir / "rules.yaml";
    std::ofstream f(path);
    f << yaml;
    return path.string();
}

// Rules matching the real config:
//   O  = 8-char org id (e.g. aabbccdd)
//   OU = 4+4 unit id  (e.g. 0001-0001)
//   Topic: /{o}/{ou}/#
static const char* SAMPLE_RULES = R"yaml(
rules:
  - id: device-own-namespace
    allow:
      publish:
        - "/{o}/{ou}/#"
      subscribe:
        - "/{o}/{ou}/#"
)yaml";

// Extended rules for layered-rule tests
static const char* LAYERED_RULES = R"yaml(
rules:
  - id: admin-full-access
    match:
      o: aabbccdd
      ou: admin
    allow:
      publish: ["#"]
      subscribe: ["#"]

  - id: device-own-namespace
    allow:
      publish:
        - "/{o}/{ou}/#"
      subscribe:
        - "/{o}/{ou}/#"
)yaml";

class RulesEngineTest : public ::testing::Test {
protected:
    std::filesystem::path tmp_dir_;

    void SetUp() override {
        tmp_dir_ = std::filesystem::temp_directory_path() / "authz_test";
        std::filesystem::create_directories(tmp_dir_);
    }
    void TearDown() override {
        std::filesystem::remove_all(tmp_dir_);
    }

    AuthzRequest make_req(const std::string& cert_subject,
                          const std::string& cn,
                          const std::string& topic,
                          const std::string& action) {
        AuthzRequest r;
        r.username     = "user";
        r.clientid     = "client";
        r.peerhost     = "127.0.0.1";
        r.cert_subject = cert_subject;
        r.cert_cn      = cn;
        r.topic        = topic;
        r.action       = action;
        return r;
    }
};

// ---- Basic allow/deny with {o}/{ou} namespace ----

TEST_F(RulesEngineTest, AllowPublishOwnNamespace) {
    RulesEngine engine(write_rules(SAMPLE_RULES, tmp_dir_));
    auto r = make_req("CN=dev1,OU=0001-0001,O=aabbccdd", "dev1",
                      "/aabbccdd/0001-0001/sensor/temp", "publish");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Allow);
}

TEST_F(RulesEngineTest, AllowSubscribeOwnNamespace) {
    RulesEngine engine(write_rules(SAMPLE_RULES, tmp_dir_));
    auto r = make_req("CN=dev1,OU=0001-0001,O=aabbccdd", "dev1",
                      "/aabbccdd/0001-0001/cmd/restart", "subscribe");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Allow);
}

TEST_F(RulesEngineTest, AllowBaseTopicWithoutSuffix) {
    // /{o}/{ou}/# also matches /{o}/{ou} itself
    RulesEngine engine(write_rules(SAMPLE_RULES, tmp_dir_));
    auto r = make_req("CN=dev1,OU=0001-0001,O=aabbccdd", "dev1",
                      "/aabbccdd/0001-0001", "subscribe");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Allow);
}

TEST_F(RulesEngineTest, DenyWrongOU) {
    // Device with OU=0001-0001 must not access OU=0002-0001 namespace
    RulesEngine engine(write_rules(SAMPLE_RULES, tmp_dir_));
    auto r = make_req("CN=dev1,OU=0001-0001,O=aabbccdd", "dev1",
                      "/aabbccdd/0002-0001/sensor/temp", "publish");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Deny);
}

TEST_F(RulesEngineTest, DenyWrongO) {
    // Device with O=aabbccdd must not access O=bbccddee namespace
    RulesEngine engine(write_rules(SAMPLE_RULES, tmp_dir_));
    auto r = make_req("CN=dev1,OU=0001-0001,O=aabbccdd", "dev1",
                      "/bbccddee/0001-0001/sensor/temp", "publish");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Deny);
}

TEST_F(RulesEngineTest, DenyMissingLeadingSlash) {
    // Pattern is /{o}/{ou}/# — topic without leading slash must not match
    RulesEngine engine(write_rules(SAMPLE_RULES, tmp_dir_));
    auto r = make_req("CN=dev1,OU=0001-0001,O=aabbccdd", "dev1",
                      "aabbccdd/0001-0001/sensor/temp", "publish");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Deny);
}

TEST_F(RulesEngineTest, DenyEmptyCertSubject) {
    RulesEngine engine(write_rules(SAMPLE_RULES, tmp_dir_));
    auto r = make_req("", "", "/aabbccdd/0001-0001/x", "publish");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Deny);
}

TEST_F(RulesEngineTest, DenyInvalidAction) {
    RulesEngine engine(write_rules(SAMPLE_RULES, tmp_dir_));
    auto r = make_req("CN=dev1,OU=0001-0001,O=aabbccdd", "dev1",
                      "/aabbccdd/0001-0001/x", "read");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Deny);
}

// ---- Different devices in same org but different OU are isolated ----

TEST_F(RulesEngineTest, TwoDevicesIsolated) {
    RulesEngine engine(write_rules(SAMPLE_RULES, tmp_dir_));

    auto r1 = make_req("CN=d1,OU=0001-0001,O=aabbccdd", "d1",
                       "/aabbccdd/0001-0001/temp", "publish");
    auto r2 = make_req("CN=d2,OU=0002-0002,O=aabbccdd", "d2",
                       "/aabbccdd/0001-0001/temp", "publish");  // wrong namespace!

    EXPECT_EQ(engine.authorize(r1), AuthzResult::Allow);
    EXPECT_EQ(engine.authorize(r2), AuthzResult::Deny);
}

// ---- Layered rules (O+OU specific + wildcard fallback) ----

TEST_F(RulesEngineTest, AdminSuperuser) {
    RulesEngine engine(write_rules(LAYERED_RULES, tmp_dir_));
    auto r = make_req("CN=admin1,OU=admin,O=aabbccdd", "admin1",
                      "/any/arbitrary/topic", "publish");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Allow);
}

TEST_F(RulesEngineTest, NonAdminFallsToNamespaceRule) {
    RulesEngine engine(write_rules(LAYERED_RULES, tmp_dir_));
    auto r = make_req("CN=dev1,OU=0001-0001,O=aabbccdd", "dev1",
                      "/aabbccdd/0001-0001/sensor", "publish");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Allow);
}

// ---- Metadata ----

TEST_F(RulesEngineTest, RulesCount) {
    RulesEngine engine(write_rules(SAMPLE_RULES, tmp_dir_));
    EXPECT_EQ(engine.rules_count(), 1u);
}

TEST_F(RulesEngineTest, Reload) {
    auto path = write_rules(SAMPLE_RULES, tmp_dir_);
    RulesEngine engine(path);
    EXPECT_EQ(engine.rules_count(), 1u);

    // Replace with a deny-all rule
    std::ofstream f(path);
    f << "rules:\n  - id: deny-all\n    deny:\n      publish: [\"#\"]\n      subscribe: [\"#\"]\n";
    f.close();

    engine.reload();
    EXPECT_EQ(engine.rules_count(), 1u);

    auto r = make_req("CN=dev1,OU=0001-0001,O=aabbccdd", "dev1",
                      "/aabbccdd/0001-0001/x", "publish");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Deny);
}
