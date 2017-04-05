//
// Created by Cody Baker on 4/4/17.
//

#include "gtest/gtest.h"
#include "../config.h"

TEST(ConfigTest, snip_parse_target_test_full) {
    const char *example = "www.test.com:12345";
    char *hostname;
    uint16_t port;
    EXPECT_TRUE(snip_parse_target(example, strlen(example), &hostname, &port));
    EXPECT_STREQ(hostname, "www.test.com");
    EXPECT_EQ(port, 12345);
}

TEST(ConfigTest, snip_parse_target_test_short_port) {
    const char *example = "www.test.com:1";
    char *hostname;
    uint16_t port;
    EXPECT_TRUE(snip_parse_target(example, strlen(example), &hostname, &port));
    EXPECT_STREQ(hostname, "www.test.com");
    EXPECT_EQ(port, 1);
}

TEST(ConfigTest, snip_parse_target_test_colon_no_port) {
    const char *example = "www.test.com:";
    char *hostname;
    uint16_t port;
    EXPECT_FALSE(snip_parse_target(example, strlen(example), &hostname, &port));
}

TEST(ConfigTest, snip_parse_target_test_port_extra) {
    const char *example = "www.test.com:12345C";
    char *hostname;
    uint16_t port;
    EXPECT_FALSE(snip_parse_target(example, strlen(example), &hostname, &port));
}

TEST(ConfigTest, snip_parse_target_test_no_port) {
    const char *example = "www.test.com";
    char *hostname;
    uint16_t port;
    EXPECT_TRUE(snip_parse_target(example, strlen(example), &hostname, &port));
    EXPECT_STREQ(hostname, "www.test.com");
    EXPECT_EQ(port, 0);
}