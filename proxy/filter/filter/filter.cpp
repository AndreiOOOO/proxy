#include <WinDivert.h>
#include <Windows.h>
#include <iostream>
#include "process_cache.h"
#include "nat_table.h"
#include "packet_filter.h"
#include "filter_util.h"

packet_filter filter;
process_cache cache;
nat_table nat;

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "WinDivert.lib")

DWORD udp_server_endpoint_addr = 0;
WORD udp_server_endpoint_port = 0;
DWORD tcp_server_endpoint_addr = 0;
WORD tcp_server_endpoint_port = 0;

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
            filter_util::ep_relation_to_str(
                filter_util::reverse_ipv4(ip_header->SrcAddr),
                ntohs(tcp_header->SrcPort),
                filter_util::reverse_ipv4(ip_header->DstAddr),
                ntohs(tcp_header->DstPort)
            );

        ip_header->SrcAddr = orig_dst_addr;
        tcp_header->SrcPort = (orig_dst_port);
        ip_header->DstAddr = orig_src_addr;
        tcp_header->DstPort = (orig_src_port);


        std::cout << "\n ret new entry " <<
            filter_util::ep_relation_to_str(
                filter_util::reverse_ipv4(ip_header->SrcAddr),
                ntohs(tcp_header->SrcPort),
                filter_util::reverse_ipv4(ip_header->DstAddr),
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

        if (filter_util::is_local_host(ip_header->DstAddr))
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

            std::cout << "\n old entry (" << 
                filter_util::reverse_ipv4(ip_header->SrcAddr) << ":"
                << ntohs(tcp_header ? tcp_header->SrcPort : udp_header->SrcPort)<< ") -> ("
                << filter_util::reverse_ipv4(ip_header->DstAddr) << ":" << 
                ntohs(tcp_header ? tcp_header->DstPort : udp_header->DstPort) << ") ||"<<

                filter_util::ep_relation_to_str(
                    filter_util::reverse_ipv4(ip_header->SrcAddr),
                    ntohs(tcp_header ? tcp_header->SrcPort : udp_header->SrcPort),
                    filter_util::reverse_ipv4(ip_header->DstAddr),
                    ntohs(tcp_header ? tcp_header->DstPort : udp_header->DstPort)
                );
            std::cout << "\n new entry " <<
                filter_util::reverse_ipv4(ip_header->SrcAddr) << ":"
                << ntohs(tcp_header ? tcp_header->SrcPort : udp_header->SrcPort) << ") -> ("
                << filter_util::reverse_ipv4(ip_header->DstAddr) << ":" <<
                ntohs(tcp_header ? tcp_header->DstPort : udp_header->DstPort) << ") ||" <<
                filter_util::ep_relation_to_str(
                    filter_util::reverse_ipv4(ip_header->SrcAddr),
                    ntohs(tcp_header ? tcp_header->SrcPort : udp_header->SrcPort),
                    filter_util::reverse_ipv4(new_dst_addr),
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

    bool retval = nat.get_original_relation_info(filter_util::reverse_ipv4(sa), htons(sp), filter_util::reverse_ipv4(da), htons(dp), original_sa, original_sp, original_da, original_dp);
    original_sa = filter_util::reverse_ipv4(original_sa);
    original_sp = ntohs(original_sp);
    original_da = filter_util::reverse_ipv4(original_da);
    original_dp = ntohs(original_dp);
    return retval;
}

bool filter_get_process_name_from_packet(
    uint32_t sa, uint16_t sp, uint32_t da, uint16_t dp,
    std::string& name
) {

    std::cout << "\n api find (" <<
        filter_util::reverse_ipv4(sa) << ":"
        << ntohs(sp) << ") -> ("
        << filter_util::reverse_ipv4(da) << ":" <<
        ntohs(dp) << ") ||" <<

        filter_util::ep_relation_to_str(
            filter_util::reverse_ipv4(sa),
            ntohs(sp),
            filter_util::reverse_ipv4(da),
            ntohs(dp)
        );
    name = cache.get_process_name_from_packet(
        filter_util::reverse_ipv4(sa), htons(sp), filter_util::reverse_ipv4(da), htons(dp)
    );

    return name.size() != 0;
}

void set_udp_server_endpoint(DWORD addr, WORD port) {
    udp_server_endpoint_addr = filter_util::reverse_ipv4(addr);
    udp_server_endpoint_port = htons(port);
}

void set_tcp_server_endpoint(DWORD addr, WORD port) {

    tcp_server_endpoint_addr = filter_util::reverse_ipv4(addr);
    tcp_server_endpoint_port = htons(port);
}

void filter_add_process(const char* process_name) {
    filter.add_process(process_name);
}