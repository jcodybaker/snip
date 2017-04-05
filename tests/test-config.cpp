//
// Created by Cody Baker on 4/4/17.
//

#include "gtest/gtest.h"
#include "../config.h"

TEST(ConfigTest, snip_parse_target_test_full) {
    const char *example = "www.test.com:12345";
    char *hostname;
    uint16_t port;
    EXPECT_TRUE(snip_parse_target(example, &hostname, &port));
    EXPECT_STREQ(hostname, "www.test.com");
    EXPECT_EQ(port, 12345);
}

TEST(ConfigTest, snip_parse_target_test_short_port) {
    const char *example = "www.test.com:1";
    char *hostname;
    uint16_t port;
    EXPECT_TRUE(snip_parse_target(example, &hostname, &port));
    EXPECT_STREQ(hostname, "www.test.com");
    EXPECT_EQ(port, 1);
}

TEST(ConfigTest, snip_parse_target_test_colon_no_port) {
    const char *example = "www.test.com:";
    char *hostname;
    uint16_t port;
    EXPECT_FALSE(snip_parse_target(example, &hostname, &port));
}

TEST(ConfigTest, snip_parse_target_test_port_extra) {
    const char *example = "www.test.com:12345C";
    char *hostname;
    uint16_t port;
    EXPECT_FALSE(snip_parse_target(example, &hostname, &port));
}

TEST(ConfigTest, snip_parse_target_test_no_port) {
    const char *example = "www.test.com";
    char *hostname;
    uint16_t port;
    EXPECT_TRUE(snip_parse_target(example, &hostname, &port));
    EXPECT_STREQ(hostname, "www.test.com");
    EXPECT_EQ(port, 0);
}

TEST(ConfigTest, snip_parse_port_test_full) {
    const char *example = "12345";
    uint16_t port;
    EXPECT_TRUE(snip_parse_port(example, &port));
    EXPECT_EQ(port, 12345);
}

TEST(ConfigTest, snip_parse_port_test_short_port) {
    const char *example = "1";
    uint16_t port;
    EXPECT_TRUE(snip_parse_port(example, &port));
    EXPECT_EQ(port, 1);
}

TEST(ConfigTest, snip_parse_port_test_port_extra) {
    const char *example = "2345C";
    uint16_t port;
    EXPECT_FALSE(snip_parse_port(example, &port));
}

TEST(ConfigTest, snip_parse_port_test_port_extra_prefix) {
    const char *example = "C1234";
    uint16_t port;
    EXPECT_FALSE(snip_parse_port(example, &port));
}

TEST(ConfigTest, snip_parse_port_test_port_extra_middle) {
    const char *example = "12C45";
    uint16_t port;
    EXPECT_FALSE(snip_parse_port(example, &port));
}