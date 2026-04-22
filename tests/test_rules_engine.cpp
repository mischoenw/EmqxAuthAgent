#include <gtest/gtest.h>
#include "rules_engine.h"
#include <fstream>
#include <filesystem>

// Write a temporary rules.yaml and return the path.
static std::string write_rules(const std::string& yaml,
                                const std::filesystem::path& dir) {
    auto path = dir / "rules.yaml";
    std::ofstream f(path);
    f << yaml;
    return path.string();
}

static const char* SAMPLE_RULES = R"yaml(
rules:
  - id: acmecorp-sensors
    match:
      o: AcmeCorp
      ou: sensors
    allow:
      publish:
        - sensors/+/data
        - devices/{cn}/status
      subscribe:
        - cmd/sensors/+

  - id: acmecorp-admin
    match:
      o: AcmeCorp
      ou: admin
    allow:
      publish: ["#"]
      subscribe: ["#"]

  - id: acmecorp-default
    match:
      o: AcmeCorp
    allow:
      subscribe:
        - announcements/#
        - status/+
    deny:
      publish: ["#"]

  - id: partnerorg-dashboard
    match:
      o: PartnerOrg
      ou: dashboard
    allow:
      subscribe:
        - sensors/#
    deny:
      publish: ["#"]
)yaml";

class RulesEngineTest : public ::testing::Test {
protected:
    std::filesystem::path tmp_dir_;
    std::string rules_path_;

    void SetUp() override {
        tmp_dir_    = std::filesystem::temp_directory_path() / "authz_test";
        std::filesystem::create_directories(tmp_dir_);
        rules_path_ = write_rules(SAMPLE_RULES, tmp_dir_);
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

TEST_F(RulesEngineTest, AllowSensorPublish) {
    RulesEngine engine(rules_path_);
    auto r = make_req("CN=dev1,OU=sensors,O=AcmeCorp", "dev1",
                      "sensors/floor1/data", "publish");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Allow);
}

TEST_F(RulesEngineTest, DenySensorWrongTopic) {
    RulesEngine engine(rules_path_);
    auto r = make_req("CN=dev1,OU=sensors,O=AcmeCorp", "dev1",
                      "cmd/floor1/data", "publish");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Deny);
}

TEST_F(RulesEngineTest, AllowCnSpecificTopic) {
    RulesEngine engine(rules_path_);
    auto r = make_req("CN=dev1,OU=sensors,O=AcmeCorp", "dev1",
                      "devices/dev1/status", "publish");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Allow);
}

TEST_F(RulesEngineTest, DenyCnWrongDevice) {
    RulesEngine engine(rules_path_);
    auto r = make_req("CN=dev1,OU=sensors,O=AcmeCorp", "dev1",
                      "devices/dev2/status", "publish");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Deny);
}

TEST_F(RulesEngineTest, AdminSuperuserPublish) {
    RulesEngine engine(rules_path_);
    auto r = make_req("CN=admin1,OU=admin,O=AcmeCorp", "admin1",
                      "any/random/topic", "publish");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Allow);
}

TEST_F(RulesEngineTest, AdminSuperuserSubscribe) {
    RulesEngine engine(rules_path_);
    auto r = make_req("CN=admin1,OU=admin,O=AcmeCorp", "admin1",
                      "cmd/sensitive", "subscribe");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Allow);
}

TEST_F(RulesEngineTest, FallthroughToDefaultSubscribe) {
    // sensors device requests announcements/# — not in OU rule, falls to O-only default
    RulesEngine engine(rules_path_);
    auto r = make_req("CN=dev1,OU=sensors,O=AcmeCorp", "dev1",
                      "announcements/general", "subscribe");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Allow);
}

TEST_F(RulesEngineTest, DefaultDenyPublishForUnknownOU) {
    RulesEngine engine(rules_path_);
    auto r = make_req("CN=d,OU=unknown,O=AcmeCorp", "d",
                      "sensors/x/data", "publish");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Deny);
}

TEST_F(RulesEngineTest, UnknownOrgDeny) {
    RulesEngine engine(rules_path_);
    auto r = make_req("CN=d,O=OtherCorp", "d",
                      "sensors/x", "subscribe");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Deny);
}

TEST_F(RulesEngineTest, MultipleOUMatchesFirstRule) {
    // Cert has both OU=sensors and OU=devices — should match sensors rule
    RulesEngine engine(rules_path_);
    auto r = make_req("CN=dev1,OU=sensors,OU=devices,O=AcmeCorp", "dev1",
                      "sensors/floor1/data", "publish");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Allow);
}

TEST_F(RulesEngineTest, EmptyCertSubjectDeny) {
    RulesEngine engine(rules_path_);
    auto r = make_req("", "", "sensors/x/data", "publish");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Deny);
}

TEST_F(RulesEngineTest, PartnerAllowSubscribe) {
    RulesEngine engine(rules_path_);
    auto r = make_req("CN=dash1,OU=dashboard,O=PartnerOrg", "dash1",
                      "sensors/floor1/data", "subscribe");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Allow);
}

TEST_F(RulesEngineTest, PartnerDenyPublish) {
    RulesEngine engine(rules_path_);
    auto r = make_req("CN=dash1,OU=dashboard,O=PartnerOrg", "dash1",
                      "sensors/floor1/data", "publish");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Deny);
}

TEST_F(RulesEngineTest, InvalidActionDeny) {
    RulesEngine engine(rules_path_);
    auto r = make_req("CN=dev1,OU=sensors,O=AcmeCorp", "dev1",
                      "sensors/floor1/data", "invalid_action");
    // "invalid_action" is neither publish nor subscribe — falls through all rules
    EXPECT_EQ(engine.authorize(r), AuthzResult::Deny);
}

TEST_F(RulesEngineTest, RulesCount) {
    RulesEngine engine(rules_path_);
    EXPECT_EQ(engine.rules_count(), 4u);
}

TEST_F(RulesEngineTest, Reload) {
    RulesEngine engine(rules_path_);
    // Overwrite with simpler rules
    write_rules(R"yaml(
rules:
  - id: allow-all
    allow:
      publish: ["#"]
      subscribe: ["#"]
)yaml", tmp_dir_);
    engine.reload();
    EXPECT_EQ(engine.rules_count(), 1u);
    auto r = make_req("CN=x,O=Any", "x", "any/topic", "publish");
    EXPECT_EQ(engine.authorize(r), AuthzResult::Allow);
}
