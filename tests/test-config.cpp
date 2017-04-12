//
// Created by Cody Baker on 4/4/17.
//

#include "gtest/gtest.h"
#include "../config.h"

TEST(ConfigTest, snip_parse_target_test_full) {
    const char *example = "www.test.com:12345";
    const char *hostname;
    uint16_t port;
    EXPECT_TRUE(snip_parse_target(example, &hostname, &port));
    EXPECT_STREQ(hostname, "www.test.com");
    EXPECT_EQ(port, 12345);
}

TEST(ConfigTest, snip_parse_target_test_short_port) {
    const char *example = "www.test.com:1";
    const char *hostname;
    uint16_t port;
    EXPECT_TRUE(snip_parse_target(example, &hostname, &port));
    EXPECT_STREQ(hostname, "www.test.com");
    EXPECT_EQ(port, 1);
}

TEST(ConfigTest, snip_parse_target_test_colon_no_port) {
    const char *example = "www.test.com:";
    const char *hostname;
    uint16_t port;
    EXPECT_FALSE(snip_parse_target(example, &hostname, &port));
}

TEST(ConfigTest, snip_parse_target_test_port_extra) {
    const char *example = "www.test.com:12345C";
    const char *hostname;
    uint16_t port;
    EXPECT_FALSE(snip_parse_target(example, &hostname, &port));
}

TEST(ConfigTest, snip_parse_target_test_no_port) {
    const char *example = "www.test.com";
    const char *hostname;
    uint16_t port;
    EXPECT_TRUE(snip_parse_target(example, &hostname, &port));
    EXPECT_STREQ(hostname, "www.test.com");
    EXPECT_EQ(port, 0);
}


/*
 * snip_parse_port
 */
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

/*
 *
 */
TEST(ConfigTest, snip_parse_config_test) {
    snip_config_t *config = snip_config_create();
    config->config_path = SNIP_TEST_CONFIGS "/example.yml";
    EXPECT_TRUE(snip_parse_config_file(config));
    EXPECT_TRUE(config->routes);
    EXPECT_TRUE(config->listeners);
    int listeners = 0;
    snip_config_listener_list_t *listener_item = config->listeners;
    while(listener_item) {
        listeners += 1;
        listener_item = listener_item->next;
    }
    EXPECT_EQ(listeners, 4);
}

TEST(ConfigTest, snip_parse_config_test_json) {
    snip_config_t *config = snip_config_create();
    config->config_path = SNIP_TEST_CONFIGS "/example.json";
    EXPECT_TRUE(snip_parse_config_file(config));
    EXPECT_TRUE(config->routes);
    EXPECT_TRUE(config->listeners);
    int listeners = 0;
    snip_config_listener_list_t *listener_item = config->listeners;
    while(listener_item) {
        listeners += 1;
        listener_item = listener_item->next;
    }
    EXPECT_EQ(listeners, 2);
}

TEST(ConfigTest, snip_parse_config_test_extra_keys) {
    snip_config_t *config = snip_config_create();
    config->config_path = SNIP_TEST_CONFIGS "/extra_keys.yml";
    EXPECT_TRUE(snip_parse_config_file(config));
    EXPECT_TRUE(config->routes);
    EXPECT_TRUE(config->listeners);
    int listeners = 0;
    snip_config_listener_list_t *listener_item = config->listeners;
    while(listener_item) {
        listeners += 1;
        listener_item = listener_item->next;
    }
    EXPECT_EQ(listeners, 2);
}

/*
 *
 */
TEST(ConfigTest, snip_parse_config_test_bind) {
    snip_config_t *config = snip_config_create();
    config->config_path = SNIP_TEST_CONFIGS "/example.yml";
    EXPECT_TRUE(snip_parse_config_file(config));
    EXPECT_TRUE(config->routes);
    EXPECT_TRUE(config->listeners);
    int listeners = 0;
    snip_config_listener_list_t *listener_item = config->listeners;
    while(listener_item) {
        if(listeners == 0) {
            EXPECT_STREQ(listener_item->value.bind_address_string, "0.0.0.0:443");
        }
        else if(listeners == 1) {
            EXPECT_STREQ(listener_item->value.bind_address_string, "*:8443");
        }
        else if(listeners == 2) {
            EXPECT_STREQ(listener_item->value.bind_address_string, "*:9443");
        }
        else if(listeners == 3) {
            EXPECT_STREQ(listener_item->value.bind_address_string, "[::]:10443");
        }
        listeners += 1;
        listener_item = listener_item->next;
    }
    EXPECT_EQ(listeners, 4);
}