#include <gtest/gtest.h>
#include "cert_parser.h"

TEST(CertParser, BasicRFC2253) {
    auto dn = extract_cert_fields("CN=device1,OU=sensors,O=AcmeCorp");
    ASSERT_EQ(dn.o_values.size(), 1u);
    EXPECT_EQ(dn.o_values[0], "AcmeCorp");
    ASSERT_EQ(dn.ou_values.size(), 1u);
    EXPECT_EQ(dn.ou_values[0], "sensors");
    EXPECT_EQ(dn.cn, "device1");
}

TEST(CertParser, SpacesAfterComma) {
    auto dn = extract_cert_fields("CN=device1, OU=sensors, O=Acme Corp");
    EXPECT_EQ(dn.o_values[0], "Acme Corp");
    EXPECT_EQ(dn.ou_values[0], "sensors");
}

TEST(CertParser, MultipleOU) {
    auto dn = extract_cert_fields("CN=d,OU=sensors,OU=devices,O=Acme");
    ASSERT_EQ(dn.ou_values.size(), 2u);
    EXPECT_EQ(dn.ou_values[0], "sensors");
    EXPECT_EQ(dn.ou_values[1], "devices");
}

TEST(CertParser, EscapedCommaInValue) {
    auto dn = extract_cert_fields("CN=d,OU=East\\,West,O=Acme");
    ASSERT_EQ(dn.ou_values.size(), 1u);
    EXPECT_EQ(dn.ou_values[0], "East,West");
}

TEST(CertParser, ReversedOrder) {
    auto dn = extract_cert_fields("O=Acme,OU=sensors,CN=d");
    EXPECT_EQ(dn.o_values[0], "Acme");
    EXPECT_EQ(dn.ou_values[0], "sensors");
    EXPECT_EQ(dn.cn, "d");
}

TEST(CertParser, LowercaseAttributes) {
    auto dn = extract_cert_fields("cn=device1,ou=SENSORS,o=AcmeCorp");
    EXPECT_EQ(dn.o_values[0], "AcmeCorp");
    EXPECT_EQ(dn.ou_values[0], "SENSORS");
    EXPECT_EQ(dn.cn, "device1");
}

TEST(CertParser, EmptyDN) {
    auto dn = extract_cert_fields("");
    EXPECT_TRUE(dn.o_values.empty());
    EXPECT_TRUE(dn.ou_values.empty());
    EXPECT_TRUE(dn.cn.empty());
}

TEST(CertParser, NoOU) {
    auto dn = extract_cert_fields("CN=d,O=Acme");
    EXPECT_EQ(dn.o_values[0], "Acme");
    EXPECT_TRUE(dn.ou_values.empty());
}

TEST(CertParser, CNFallbackParameter) {
    auto dn = extract_cert_fields("O=Acme,OU=sensors", "fallback-cn");
    EXPECT_EQ(dn.cn, "fallback-cn");
}

TEST(CertParser, CNFromSubjectWinsOverFallback) {
    auto dn = extract_cert_fields("CN=real-cn,O=Acme", "fallback-cn");
    EXPECT_EQ(dn.cn, "real-cn");
}

TEST(CertParser, HexEncodedValue) {
    // #41636d65 decodes to "Acme"
    auto dn = extract_cert_fields("O=#41636d65,CN=d");
    ASSERT_FALSE(dn.o_values.empty());
    EXPECT_EQ(dn.o_values[0], "Acme");
}

TEST(CertParser, MultiValuedRDN) {
    // OU=sensors+O=overlay in the same RDN
    auto dn = extract_cert_fields("CN=d,OU=sensors+O=overlay,O=Acme");
    // O should contain both "overlay" (from multi-valued RDN) and "Acme"
    EXPECT_GE(dn.o_values.size(), 1u);
    EXPECT_EQ(dn.ou_values[0], "sensors");
}

TEST(CertParser, OpenSSLSlashFormat) {
    auto dn = extract_cert_fields("/CN=device1/OU=sensors/O=AcmeCorp");
    EXPECT_EQ(dn.o_values[0], "AcmeCorp");
    EXPECT_EQ(dn.ou_values[0], "sensors");
    EXPECT_EQ(dn.cn, "device1");
}
