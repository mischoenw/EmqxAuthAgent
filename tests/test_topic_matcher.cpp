#include <gtest/gtest.h>
#include "topic_matcher.h"

// Helper: build a TopicPlaceholders with only cn set
static TopicPlaceholders ph_cn(const std::string& cn) {
    return TopicPlaceholders{cn, "", ""};
}

static TopicPlaceholders ph(const std::string& cn,
                             const std::string& o,
                             const std::string& ou) {
    return TopicPlaceholders{cn, o, ou};
}

// ---- exact match ----
TEST(TopicMatcher, ExactMatch) {
    EXPECT_TRUE(matches_topic("sensors/floor1/data", "sensors/floor1/data"));
}

TEST(TopicMatcher, ExactNoMatch) {
    EXPECT_FALSE(matches_topic("sensors/floor1/data", "sensors/floor2/data"));
}

// ---- single-level wildcard + ----
TEST(TopicMatcher, SingleWildcard) {
    EXPECT_TRUE(matches_topic("sensors/+/data", "sensors/floor1/data"));
    EXPECT_TRUE(matches_topic("sensors/+/data", "sensors/x/data"));
}

TEST(TopicMatcher, SingleWildcardNoMultiLevel) {
    EXPECT_FALSE(matches_topic("sensors/+/data", "sensors/a/b/data"));
}

TEST(TopicMatcher, SingleWildcardAtRoot) {
    EXPECT_TRUE(matches_topic("+/data", "floor1/data"));
    EXPECT_FALSE(matches_topic("+/data", "a/b/data"));
}

// ---- multi-level wildcard # ----
TEST(TopicMatcher, HashMatchesMultiLevel) {
    EXPECT_TRUE(matches_topic("sensors/#", "sensors/a/b/c"));
}

TEST(TopicMatcher, HashMatchesPrefix) {
    // sensors/# matches "sensors" itself (base level, no trailing slash)
    EXPECT_TRUE(matches_topic("sensors/#", "sensors"));
}

TEST(TopicMatcher, HashAtRoot) {
    EXPECT_TRUE(matches_topic("#", "any/topic/at/all"));
    EXPECT_TRUE(matches_topic("#", "single"));
}

TEST(TopicMatcher, HashWithLeadingSlash) {
    // Leading slash creates an empty first segment
    EXPECT_TRUE(matches_topic("/aabbccdd/0001-0001/#", "/aabbccdd/0001-0001/sensor/temp"));
    EXPECT_TRUE(matches_topic("/aabbccdd/0001-0001/#", "/aabbccdd/0001-0001"));
    EXPECT_FALSE(matches_topic("/aabbccdd/0001-0001/#", "/aabbccdd/0002-0001/sensor"));
}

TEST(TopicMatcher, HashMustBeLast) {
    EXPECT_THROW(validate_topic_pattern("sensors/#/data"), std::invalid_argument);
}

TEST(TopicMatcher, EmptyPatternInvalid) {
    EXPECT_THROW(validate_topic_pattern(""), std::invalid_argument);
}

// ---- {cn} placeholder ----
TEST(TopicMatcher, CnSubstitution) {
    EXPECT_TRUE(matches_topic("devices/{cn}/cmd", "devices/dev1/cmd", ph_cn("dev1")));
}

TEST(TopicMatcher, CnWrongDevice) {
    EXPECT_FALSE(matches_topic("devices/{cn}/cmd", "devices/dev2/cmd", ph_cn("dev1")));
}

TEST(TopicMatcher, CnWithRegexChars) {
    // CN "dev.*" must be treated as a literal string, not a regex
    EXPECT_TRUE( matches_topic("devices/{cn}/cmd", "devices/dev.*/cmd", ph_cn("dev.*")));
    EXPECT_FALSE(matches_topic("devices/{cn}/cmd", "devices/devXYZ/cmd", ph_cn("dev.*")));
}

TEST(TopicMatcher, CnWithSlashIsSafe) {
    EXPECT_FALSE(matches_topic("devices/{cn}/cmd", "devices/a/b/cmd", ph_cn("a/b")));
}

// ---- {o} and {ou} placeholders ----
TEST(TopicMatcher, OAndOuSubstitution) {
    // Pattern: /{o}/{ou}/# with O=aabbccdd, OU=0001-0001
    TopicPlaceholders p = ph("dev1", "aabbccdd", "0001-0001");
    EXPECT_TRUE( matches_topic("/{o}/{ou}/#", "/aabbccdd/0001-0001/sensor/temp", p));
    EXPECT_TRUE( matches_topic("/{o}/{ou}/#", "/aabbccdd/0001-0001", p));
    EXPECT_FALSE(matches_topic("/{o}/{ou}/#", "/aabbccdd/0002-0001/sensor", p));
    EXPECT_FALSE(matches_topic("/{o}/{ou}/#", "/bbccddee/0001-0001/sensor", p));
}

TEST(TopicMatcher, OWithRegexChars) {
    // O value containing regex-special chars must be escaped
    TopicPlaceholders p = ph("cn", "ab.cd+ef", "0001-0001");
    EXPECT_TRUE( matches_topic("/{o}/{ou}/#", "/ab.cd+ef/0001-0001/x", p));
    EXPECT_FALSE(matches_topic("/{o}/{ou}/#", "/abXcdYef/0001-0001/x", p));
}

TEST(TopicMatcher, AllPlaceholdersCombined) {
    TopicPlaceholders p = ph("mydevice", "aabbccdd", "0001-0001");
    EXPECT_TRUE(matches_topic("/{o}/{ou}/{cn}/data",
                              "/aabbccdd/0001-0001/mydevice/data", p));
}

// ---- combined wildcards ----
TEST(TopicMatcher, PlusAndHash) {
    EXPECT_TRUE(matches_topic("+/sensors/#", "floor1/sensors/temp/room2"));
}
