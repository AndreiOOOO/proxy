#ifndef PROCESS_CACHE_H
#define PROCESS_CACHE_H

#include <Windows.h>
#include <string>
#include <unordered_map>

class process_cache {
public:
    process_cache();
    ~process_cache();

    std::string get_process_name(DWORD pid);
    std::string get_process_name_from_packet(DWORD src_addr, WORD src_port, DWORD dst_addr, WORD dst_port);
    std::string get_process_name_from_tcp_table(DWORD src_addr, WORD src_port, DWORD dst_addr, WORD dst_port);
    std::string get_process_name_from_udp_table(DWORD src_addr, WORD src_port);

private:
    std::string get_process_name_from_system(DWORD pid);

    std::unordered_map<DWORD, std::string> cache;
};

#endif // PROCESS_CACHE_H