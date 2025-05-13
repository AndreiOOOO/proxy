#ifndef FILTER_UTIL_H
#define FILTER_UTIL_H

#include <string>
#include <cstdint>

namespace filter_util {
    std::string uint32_to_ip(uint32_t addr);
    std::string ep_relation_to_str(uint32_t src_addr, uint16_t src_port, uint32_t dst_addr, uint16_t dst_port);
    uint32_t reverse_ipv4(uint32_t addr);
    bool is_local_host(uint32_t address);
}

#endif // FILTER_UTIL_H