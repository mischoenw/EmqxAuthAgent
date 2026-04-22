#include <gtest/gtest.h>
#include "topic_matcher.h"

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
    // + must not span multiple levels
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
    // sensors/# should also match "sensors" itself (base level)
    EXPECT_TRUE(matches_topic("sensors/#", "sensors"));
}

TEST(TopicMatcher, HashAtRoot) {
    // Bare # matches everything
    EXPECT_TRUE(matches_topic("#", "any/topic/at/all"));
    EXPECT_TRUE(matches_topic("#", "single"));
}

TEST(TopicMatcher, HashMustBeLast) {
    EXPECT_THROW(validate_topic_pattern("sensors/#/data"),
                 std::invalid_argument);
}

TEST(TopicMatcher, EmptyPatternInvalid) {
    EXPECT_THROW(validate_topic_pattern(""), std::invalid_argument);
}

// ---- {cn} placeholder ----
TEST(TopicMatcher, CnSubstitution) {
    EXPECT_TRUE(matches_topic("devices/{cn}/cmd", "devices/dev1/cmd", "dev1"));
}

TEST(TopicMatcher, CnWrongDevice) {
    EXPECT_FALSE(matches_topic("devices/{cn}/cmd", "devices/dev2/cmd", "dev1"));
}

TEST(TopicMatcher, CnWithRegexChars) {
    // CN like "dev.*" must be treated literally, not as a regex
    EXPECT_TRUE( matches_topic("devices/{cn}/cmd", "devices/dev.*/cmd", "dev.*"));
    EXPECT_FALSE(matches_topic("devices/{cn}/cmd", "devices/devXYZ/cmd", "dev.*"));
}

TEST(TopicMatcher, CnWithSlashIsSafe) {
    // Even if CN somehow contains '/', the match should just fail (no regex injection)
    EXPECT_FALSE(matches_topic("devices/{cn}/cmd", "devices/a/b/cmd", "a/b"));
}

// ---- combined ----
TEST(TopicMatcher, PlusAndHash) {
    EXPECT_TRUE(matches_topic("+/sensors/#", "floor1/sensors/temp/room2"));
}
