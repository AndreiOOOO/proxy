#include "process_cache.h"
#include <iphlpapi.h>
#include <psapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")

process_cache::process_cache() {}

process_cache::~process_cache() {}

std::string process_cache::get_process_name(DWORD pid) {
    auto it = cache.find(pid);
    if (it != cache.end()) {
        return it->second;
    }
    std::string process_name = get_process_name_from_system(pid);
    cache[pid] = process_name;
    return process_name;
}

std::string process_cache::get_process_name_from_packet(DWORD src_addr, WORD src_port, DWORD dst_addr, WORD dst_port) {
    // Verificar se o pacote é TCP
    std::string process_name = get_process_name_from_tcp_table(src_addr, src_port, dst_addr, dst_port);
    if (!process_name.empty()) {
        return process_name;
    }

    // Verificar se o pacote é UDP
    process_name = get_process_name_from_udp_table(src_addr, src_port);
    return process_name;
}

std::string process_cache::get_process_name_from_tcp_table(DWORD src_addr, WORD src_port, DWORD dst_addr, WORD dst_port) {
    PMIB_TCPTABLE2 tcp_table;
    DWORD tcp_table_size = 0;
    GetTcpTable2(NULL, &tcp_table_size, TRUE);
    tcp_table = (PMIB_TCPTABLE2)malloc(tcp_table_size);
    GetTcpTable2(tcp_table, &tcp_table_size, TRUE);

    std::string process_name;
    for (DWORD i = 0; i < tcp_table->dwNumEntries; i++) {
        if (tcp_table->table[i].dwLocalAddr == src_addr &&
            (tcp_table->table[i].dwLocalPort) == (src_port) &&
            tcp_table->table[i].dwRemoteAddr == dst_addr &&
            (tcp_table->table[i].dwRemotePort) == (dst_port)) {
            process_name = get_process_name(tcp_table->table[i].dwOwningPid);
            break;
        }
    }
    free(tcp_table);
    return process_name;
}

std::string process_cache::get_process_name_from_udp_table(DWORD src_addr, WORD src_port) {
    PMIB_UDPTABLE_OWNER_PID udp_table;
    DWORD udp_table_size = 0;
    GetExtendedUdpTable(NULL, &udp_table_size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);
    udp_table = (PMIB_UDPTABLE_OWNER_PID)malloc(udp_table_size);
    GetExtendedUdpTable(udp_table, &udp_table_size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0);

    std::string process_name;
    for (DWORD i = 0; i < udp_table->dwNumEntries; i++) {
        if (udp_table->table[i].dwLocalAddr == src_addr &&
            ntohs(udp_table->table[i].dwLocalPort) == ntohs(src_port)) {
            process_name = get_process_name(udp_table->table[i].dwOwningPid);
            break;
        }
    }
    free(udp_table);
    return process_name;
}

std::string process_cache::get_process_name_from_system(DWORD pid) {
    HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (h_process) {
        char process_name[MAX_PATH];
        GetProcessImageFileName(h_process, process_name, MAX_PATH);
        CloseHandle(h_process);
        // Obter apenas o nome do arquivo sem o path
        char* file_name = strrchr(process_name, '\\');
        if (file_name) {
            file_name++; // Pular o caractere '\\'
            return file_name;
        }
        else {
            return process_name;
        }
    }
    return "";
}