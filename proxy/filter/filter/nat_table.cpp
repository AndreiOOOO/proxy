#include "nat_table.h"

void nat_table::add_entry(DWORD orig_src_addr, WORD orig_src_port, DWORD orig_dst_addr, WORD orig_dst_port, DWORD new_dst_addr, WORD new_dst_port) {
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

bool nat_table::get_original_relation_info(uint32_t sa, uint16_t sp, uint32_t da, uint16_t dp, uint32_t& original_sa, uint16_t& original_sp, uint32_t& original_da, uint16_t& original_dp) {
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