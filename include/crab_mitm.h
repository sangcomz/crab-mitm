#ifndef CRAB_MITM_H
#define CRAB_MITM_H

#include <stdbool.h>
#include <stdint.h>

typedef struct CrabProxyHandle CrabProxyHandle;

enum {
    CRAB_OK = 0,
    CRAB_ERR_INVALID_ARG = 1,
    CRAB_ERR_STATE = 2,
    CRAB_ERR_IO = 3,
    CRAB_ERR_CA = 4,
    CRAB_ERR_INTERNAL = 255
};

typedef struct {
    int32_t code;   /* CRAB_OK on success */
    char *message;  /* NULL on success. Caller must free with crab_free_string. */
} CrabResult;

/* user_data must remain valid until crab_set_log_callback(NULL, NULL) returns. */
typedef void (*CrabLogCallback)(void *user_data, uint8_t level, const char *message);

void crab_free_string(char *ptr);

void crab_set_log_callback(CrabLogCallback callback, void *user_data);

CrabResult crab_proxy_create(CrabProxyHandle **out_handle, const char *listen_addr);
CrabResult crab_proxy_set_listen_addr(CrabProxyHandle *handle, const char *listen_addr);
CrabResult crab_proxy_set_port(CrabProxyHandle *handle, uint16_t port);
CrabResult crab_proxy_load_ca(CrabProxyHandle *handle, const char *cert_path, const char *key_path);
CrabResult crab_proxy_set_inspect_enabled(CrabProxyHandle *handle, bool enabled);
CrabResult crab_proxy_set_throttle_enabled(CrabProxyHandle *handle, bool enabled);
CrabResult crab_proxy_set_throttle_latency_ms(CrabProxyHandle *handle, uint64_t latency_ms);
CrabResult crab_proxy_set_throttle_downstream_bps(CrabProxyHandle *handle, uint64_t downstream_bps);
CrabResult crab_proxy_set_throttle_upstream_bps(CrabProxyHandle *handle, uint64_t upstream_bps);
CrabResult crab_proxy_set_throttle_only_selected_hosts(CrabProxyHandle *handle, bool enabled);
CrabResult crab_proxy_throttle_hosts_clear(CrabProxyHandle *handle);
CrabResult crab_proxy_throttle_hosts_add(CrabProxyHandle *handle, const char *matcher);
CrabResult crab_proxy_set_client_allowlist_enabled(CrabProxyHandle *handle, bool enabled);
CrabResult crab_proxy_client_allowlist_clear(CrabProxyHandle *handle);
CrabResult crab_proxy_client_allowlist_add_ip(CrabProxyHandle *handle, const char *ip_addr);
CrabResult crab_proxy_set_transparent_enabled(CrabProxyHandle *handle, bool enabled);
CrabResult crab_proxy_set_transparent_port(CrabProxyHandle *handle, uint16_t port);
CrabResult crab_proxy_rules_clear(CrabProxyHandle *handle);
CrabResult crab_proxy_rules_add_allow(
    CrabProxyHandle *handle,
    const char *matcher
);
CrabResult crab_proxy_rules_add_map_local_file(
    CrabProxyHandle *handle,
    const char *matcher,
    const char *file_path,
    uint16_t status_code,
    const char *content_type /* nullable */
);
CrabResult crab_proxy_rules_add_map_local_text(
    CrabProxyHandle *handle,
    const char *matcher,
    const char *text,
    uint16_t status_code,
    const char *content_type /* nullable */
);
CrabResult crab_proxy_rules_add_status_rewrite(
    CrabProxyHandle *handle,
    const char *matcher,
    int32_t from_status_code /* negative means any */,
    uint16_t to_status_code
);
CrabResult crab_proxy_start(CrabProxyHandle *handle);
CrabResult crab_proxy_stop(CrabProxyHandle *handle);
bool crab_proxy_is_running(const CrabProxyHandle *handle);
void crab_proxy_destroy(CrabProxyHandle *handle);

enum {
    CRAB_CA_KEY_ALGORITHM_ECDSA_P256 = 0,
    CRAB_CA_KEY_ALGORITHM_RSA_2048 = 1,
    CRAB_CA_KEY_ALGORITHM_RSA_4096 = 2
};

CrabResult crab_ca_generate(const char *common_name, uint32_t days, const char *out_cert, const char *out_key);
CrabResult crab_ca_generate_with_algorithm(
    const char *common_name,
    uint32_t days,
    const char *out_cert,
    const char *out_key,
    uint32_t key_algorithm
);

#endif
