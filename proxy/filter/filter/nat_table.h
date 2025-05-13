#ifndef NAT_TABLE_H
#define NAT_TABLE_H

#include <Windows.h>
#include <vector>
#include <mutex>

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

    void add_entry(DWORD orig_src_addr, WORD orig_src_port, DWORD orig_dst_addr, WORD orig_dst_port, DWORD new_dst_addr, WORD new_dst_port);
    bool get_original_relation_info(uint32_t sa, uint16_t sp, uint32_t da, uint16_t dp, uint32_t& original_sa, uint16_t& original_sp, uint32_t& original_da, uint16_t& original_dp);

private:
    std::vector<nat_entry> entries;
    std::mutex mtx;
};

#endif // NAT_TABLE_H