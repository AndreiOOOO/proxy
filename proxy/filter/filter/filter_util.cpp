#include "filter_util.h"
#include <sstream>

namespace filter_util {
    std::string uint32_to_ip(uint32_t addr) {
        return std::to_string((addr >> 24) & 0xFF) + "." +
            std::to_string((addr >> 16) & 0xFF) + "." +
            std::to_string((addr >> 8) & 0xFF) + "." +
            std::to_string(addr & 0xFF);
    }

    std::string ep_relation_to_str(uint32_t src_addr, uint16_t src_port, uint32_t dst_addr, uint16_t dst_port) {
        std::string src_ip = uint32_to_ip(src_addr);
        std::string dst_ip = uint32_to_ip(dst_addr);

        std::string relation_str = src_ip + ":" + std::to_string(src_port) +
            " -> " + dst_ip + ":" + std::to_string(dst_port);

        return relation_str;
    }

    uint32_t reverse_ipv4(uint32_t addr) {
        return ((addr & 0x000000FF) << 24) |
            ((addr & 0x0000FF00) << 8) |
            ((addr & 0x00FF0000) >> 8) |
            ((addr & 0xFF000000) >> 24);
    }

    bool is_local_host(uint32_t address) {
        if (address == 0)
            return true;

        // Verifica se o endereço IP é de loopback (127.0.0.1)
        if ((address & 0xFF000000) == 0x7F000000) {
            return true;
        }

        // Verifica se o endereço IP é de uma interface local
        // Isso pode variar dependendo da configuração da rede
        // Aqui estamos considerando apenas os endereços IP privados
        if ((address & 0xFF000000) == 0x0A000000 || // 10.0.0.0/8
            (address & 0xFFF00000) == 0xAC100000 || // 172.16.0.0/12
            (address & 0xFFFF0000) == 0xC0A80000) { // 192.168.0.0/16
            return true;
        }

        return false;
    }
}