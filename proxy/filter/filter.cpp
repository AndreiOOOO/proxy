#include <WinDivert.h>
#include <Windows.h>
#include <iphlpapi.h>
#include <psapi.h>
#include <unordered_map>
#include <string>
#include <unordered_set>
#include <iostream>
#include <algorithm>
#include <mutex>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "WinDivert.lib")

class process_cache {
public:
    process_cache() {}
    ~process_cache() {}

    std::string get_process_name(DWORD pid) {
        auto it = cache.find(pid);
        if (it != cache.end()) {
            return it->second;
        }
        std::string process_name = get_process_name_from_system(pid);
        cache[pid] = process_name;
        return process_name;
    }

    std::string get_process_name_from_packet(DWORD src_addr, WORD src_port, DWORD dst_addr, WORD dst_port) {
        // Verificar se o pacote é TCP
        std::string process_name = get_process_name_from_tcp_table(src_addr, src_port, dst_addr, dst_port);
        if (!process_name.empty()) {
            return process_name;
        }

        // Verificar se o pacote é UDP
        process_name = get_process_name_from_udp_table(src_addr, src_port);
        return process_name;
    }

    std::string get_process_name_from_tcp_table(DWORD src_addr, WORD src_port, DWORD dst_addr, WORD dst_port) {
        PMIB_TCPTABLE2 tcp_table;
        DWORD tcp_table_size = 0;
        GetTcpTable2(NULL, &tcp_table_size, TRUE);
        tcp_table = (PMIB_TCPTABLE2)malloc(tcp_table_size);
        GetTcpTable2(tcp_table, &tcp_table_size, TRUE);

        std::string process_name;
        for (DWORD i = 0; i < tcp_table->dwNumEntries; i++) {
            if (tcp_table->table[i].dwLocalAddr == src_addr &&
                ntohs(tcp_table->table[i].dwLocalPort) == ntohs(src_port) &&
                tcp_table->table[i].dwRemoteAddr == dst_addr &&
                ntohs(tcp_table->table[i].dwRemotePort) == ntohs(dst_port)) {
                process_name = get_process_name(tcp_table->table[i].dwOwningPid);
                break;
            }
        }
        free(tcp_table);
        return process_name;
    }

    std::string get_process_name_from_udp_table(DWORD src_addr, WORD src_port) {
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


private:
  /*  std::string get_process_name_from_system(DWORD pid) {
        HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (h_process) {
            char process_name[MAX_PATH];
            GetProcessImageFileName(h_process, process_name, MAX_PATH);
            CloseHandle(h_process);
            return process_name;
        }
        return "";
    }*/

    std::string get_process_name_from_system(DWORD pid) {
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

    std::unordered_map<DWORD, std::string> cache;
};

class packet_filter {
private:
    std::unordered_set<std::string> filtered_processes;
    std::mutex mtx;

public:
    void add_process(std::string process) {
        std::lock_guard<std::mutex> lock(mtx);
        std::transform(process.begin(), process.end(), process.begin(), ::tolower);
        filtered_processes.insert(process);
    }

    bool check_process(std::string process) {
        std::lock_guard<std::mutex> lock(mtx);
        std::transform(process.begin(), process.end(), process.begin(), ::tolower);
        return filtered_processes.find(process) != filtered_processes.end();
    }
};



class nat_table {
public:
    struct nat_entry {
        DWORD orig_src_addr;
        WORD orig_src_port;
        DWORD orig_dst_addr;
        WORD orig_dst_port;
        DWORD new_dst_addr;
        WORD new_dst_port;
    };

private:
    std::vector<nat_entry> entries;
    std::mutex mtx;

public:
    void add_entry(DWORD orig_src_addr, WORD orig_src_port, DWORD orig_dst_addr, WORD orig_dst_port, DWORD new_dst_addr, WORD new_dst_port) {
        std::lock_guard<std::mutex> lock(mtx);
        for (auto& entry : entries) {
            if (entry.orig_src_addr == orig_src_addr && entry.orig_src_port == orig_src_port &&
                entry.orig_dst_addr == orig_dst_addr && entry.orig_dst_port == orig_dst_port) {
                // Entrada já existe, podemos atualizar ou ignorar
                return;
            }
        }
        nat_entry entry;
        entry.orig_src_addr = orig_src_addr;
        entry.orig_src_port = orig_src_port;
        entry.orig_dst_addr = orig_dst_addr;
        entry.orig_dst_port = orig_dst_port;
        entry.new_dst_addr = new_dst_addr;
        entry.new_dst_port = new_dst_port;
        entries.push_back(entry);
    }

    bool get_original_relation_info(
        uint32_t sa, uint16_t sp, uint32_t da, uint16_t dp,
        uint32_t& original_sa, uint16_t& original_sp, uint32_t& original_da, uint16_t& original_dp
    ) {
        std::lock_guard<std::mutex> lock(mtx);
        for (auto& entry : entries) {
            if (
                ((entry.new_dst_addr == da || da == 0) && entry.new_dst_port == dp)
                &&
                (entry.orig_src_addr == sa && entry.orig_src_port == sp)
                ) {
                original_sa = entry.orig_src_addr;
                original_sp = entry.orig_src_port;
                original_da = entry.orig_dst_addr;
                original_dp = entry.orig_dst_port;
                return true;
            }
        }
        return false;
    }
};

DWORD udp_server_endpoint_addr = 0;
WORD udp_server_endpoint_port = 0;
DWORD tcp_server_endpoint_addr = 0;
WORD tcp_server_endpoint_port = 0;

packet_filter filter;
process_cache cache;
nat_table nat;

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

PWINDIVERT_IPHDR get_ip_header(PVOID packet) {
    return (PWINDIVERT_IPHDR)packet;
}

PWINDIVERT_UDPHDR get_udp_header(PWINDIVERT_IPHDR ip_header) {
    return (PWINDIVERT_UDPHDR)((PBYTE)ip_header + ip_header->HdrLength * 4);
}

PWINDIVERT_TCPHDR get_tcp_header(PWINDIVERT_IPHDR ip_header) {
    return (PWINDIVERT_TCPHDR)((PBYTE)ip_header + ip_header->HdrLength * 4);
}

bool translate_response_udp_packet(PWINDIVERT_IPHDR ip_header, PWINDIVERT_UDPHDR udp_header, nat_table& nat) {
    uint32_t orig_dst_addr;
    uint16_t orig_dst_port;
    uint32_t orig_src_addr;
    uint16_t orig_src_port;

 /*   if (nat.get_original_relation_info(ip_header->SrcAddr, (udp_header->SrcPort), orig_src_addr, orig_src_port, orig_dst_addr, orig_dst_port)) {
        ip_header->DstAddr = orig_src_addr;
        udp_header->DstPort = (orig_src_port);
        ip_header->SrcAddr = orig_dst_addr;
        udp_header->SrcPort = orig_dst_port;
        return true;
    }*/
    return false;
}

bool translate_response_tcp_packet(PWINDIVERT_IPHDR ip_header, PWINDIVERT_TCPHDR tcp_header, nat_table& nat) {
    uint32_t orig_dst_addr;
    uint16_t orig_dst_port;
    uint32_t orig_src_addr;
    uint16_t orig_src_port;

    if (nat.get_original_relation_info(
        ip_header->DstAddr, (tcp_header->DstPort),
        ip_header->SrcAddr, (tcp_header->SrcPort),

        orig_src_addr, orig_src_port, orig_dst_addr, orig_dst_port)) {

        std::cout << "\n ret old entry " <<
            ep_relation_to_str(
                reverse_ipv4(ip_header->SrcAddr),
                ntohs(tcp_header->SrcPort),
                reverse_ipv4(ip_header->DstAddr),
                ntohs(tcp_header->DstPort)
            );

        ip_header->SrcAddr = orig_dst_addr;
        tcp_header->SrcPort = (orig_dst_port);
        ip_header->DstAddr = orig_src_addr;
        tcp_header->DstPort = (orig_src_port);

       
        std::cout << "\n ret new entry " <<
            ep_relation_to_str(
                reverse_ipv4(ip_header->SrcAddr),
                ntohs(tcp_header->SrcPort),
                reverse_ipv4(ip_header->DstAddr),
                ntohs(tcp_header->DstPort)
            );

        return true;
    }
    return false;
}

bool is_response_packet(PVOID packet, nat_table& nat) {
    PWINDIVERT_IPHDR ip_header = get_ip_header(packet);

    if (ip_header->Protocol == IPPROTO_UDP) {
        PWINDIVERT_UDPHDR udp_header = get_udp_header(ip_header);
        if (ip_header->SrcAddr != udp_server_endpoint_addr)
            return false;
        if (udp_header->SrcPort != udp_server_endpoint_port)
            return false;
        return
            translate_response_udp_packet(ip_header, udp_header, nat);
    }
    else if (ip_header->Protocol == IPPROTO_TCP) {
        PWINDIVERT_TCPHDR tcp_header = get_tcp_header(ip_header);
        if (ip_header->SrcAddr != tcp_server_endpoint_addr)
            return false;
        if (tcp_header->SrcPort != tcp_server_endpoint_port)
            return false;
        return
            translate_response_tcp_packet(ip_header, tcp_header, nat);
    }

    return
        false;
}

int run_windivert() {
    HANDLE handle = WinDivertOpen("outbound and tcp", WINDIVERT_LAYER_NETWORK, 0, 0);
    if (handle == INVALID_HANDLE_VALUE) {
        std::cout << "Erro ao abrir o handle do WinDivert" << std::endl;
        return 1;
    }

   

    filter.add_process("tibia.exe");
    filter.add_process("tibia-1746908820.exe");

    
    while (true) {
        UINT8 packet[65535];
        UINT packet_len = sizeof(packet);
        WINDIVERT_ADDRESS addr;
        if (!WinDivertRecv(handle, packet, packet_len, &packet_len, &addr)) {
            continue;
        }

        PWINDIVERT_IPHDR ip_header;
        PWINDIVERT_TCPHDR tcp_header;
        PWINDIVERT_UDPHDR udp_header;
        PVOID data;
        UINT data_len;
        if (!WinDivertHelperParsePacket(packet, packet_len, &ip_header, NULL, NULL, NULL, NULL, &tcp_header, &udp_header, &data, &data_len, NULL, NULL)) {
            BOOL res = WinDivertSend(handle, packet, packet_len, NULL, &addr);
            continue;
        }

        if (is_response_packet(packet, nat)) {
            WinDivertHelperCalcChecksums(packet, packet_len, NULL, 0);
            BOOL res = WinDivertSend(handle, packet, packet_len, NULL, &addr);
            continue;
        }

        if (is_local_host(ip_header->DstAddr))
        {
            BOOL res = WinDivertSend(handle, packet, packet_len, NULL, &addr);
            continue;
        }

        std::string process_name;
        if (ip_header->Protocol == IPPROTO_TCP) {
            process_name = cache.get_process_name_from_packet(ip_header->SrcAddr, tcp_header->SrcPort, ip_header->DstAddr, tcp_header->DstPort);
        }
        else if (ip_header->Protocol == IPPROTO_UDP) {
            process_name = cache.get_process_name_from_packet(ip_header->SrcAddr, udp_header->SrcPort, ip_header->DstAddr, udp_header->DstPort);
        }


        if (filter.check_process(process_name)) {
            std::cout << "\n" << process_name;
            DWORD new_dst_addr;
            WORD new_dst_port;

            if (ip_header->Protocol == IPPROTO_TCP) {
                new_dst_addr = tcp_server_endpoint_addr;
                new_dst_port = tcp_server_endpoint_port;
            }
            else if (ip_header->Protocol == IPPROTO_UDP) {
                new_dst_addr = udp_server_endpoint_addr;
                new_dst_port = udp_server_endpoint_port;
            }

           
            if (ip_header->Protocol == IPPROTO_TCP) {
                nat.add_entry(
                    (ip_header->SrcAddr),
                    (tcp_header->SrcPort),
                    (ip_header->DstAddr),
                    (tcp_header->DstPort),
                    (new_dst_addr),
                    (new_dst_port)
                );
            }
            else if (ip_header->Protocol == IPPROTO_UDP) {
                nat.add_entry(
                    (ip_header->SrcAddr),
                    (udp_header->SrcPort),
                    (ip_header->DstAddr),
                    (udp_header->DstPort),
                    (new_dst_addr),
                    (new_dst_port)
                );
            }

            std::cout << "\n old entry " <<
                ep_relation_to_str(
                    reverse_ipv4(ip_header->SrcAddr),
                    ntohs(tcp_header->SrcPort),
                    reverse_ipv4(ip_header->DstAddr),
                    ntohs(tcp_header->DstPort)
                );
            std::cout << "\n new entry " <<
                ep_relation_to_str(
                    reverse_ipv4(ip_header->SrcAddr),
                    ntohs(tcp_header->SrcPort),
                    reverse_ipv4(new_dst_addr),
                    ntohs(new_dst_port)
                );


            ip_header->DstAddr = new_dst_addr;
            if (ip_header->Protocol == IPPROTO_TCP) {
                tcp_header->DstPort = new_dst_port;
            }
            else if (ip_header->Protocol == IPPROTO_UDP) {
                udp_header->DstPort = new_dst_port;
            }


            BOOL res = WinDivertHelperCalcChecksums(packet, packet_len, NULL, 0);
            std::cout << "\n sun res " << res;
            res = WinDivertSend(handle, packet, packet_len, NULL, &addr);

            std::cout << "\n send res " << res;
        }
        else
        {
            BOOL res = WinDivertSend(handle, packet, packet_len, NULL, &addr);
        }
    }

    WinDivertClose(handle);
    return 0;

}

bool filter_get_original_relation_info(
    uint32_t sa, uint16_t sp, uint32_t da, uint16_t dp,
    uint32_t& original_sa, uint16_t& original_sp, uint32_t& original_da, uint16_t& original_dp
) {
    
    bool retval =  nat.get_original_relation_info( reverse_ipv4(da), htons(dp), reverse_ipv4(sa), htons(sp), original_sa, original_sp, original_da, original_dp);
    original_sa = reverse_ipv4(original_sa);
    original_sp = ntohs(original_sp);
    original_da = reverse_ipv4(original_da);
    original_dp = ntohs(original_dp);
    return retval;
}

void set_udp_server_endpoint(DWORD addr, WORD port) {
    udp_server_endpoint_addr = reverse_ipv4(addr);
    udp_server_endpoint_port = htons(port);
}

void set_tcp_server_endpoint(DWORD addr, WORD port) {
    
    tcp_server_endpoint_addr = reverse_ipv4(addr);
    tcp_server_endpoint_port = htons(port);
}

void filter_add_process(const char* process_name) {
    filter.add_process(process_name);
}
