#include <boost/asio.hpp>
#include <memory>
#include <functional>
#include <unordered_map>
#include <string>
#include <iostream>
extern void tcp_server_init(boost::asio::io_context& io_context, unsigned short port);
extern void tcp_server_async_recv(std::function<void(uint32_t, std::shared_ptr<std::string>)> handler);
extern void tcp_server_add_data(uint32_t relation_id, const std::string& data);
extern bool tcp_server_get_original_relation(uint32_t relation_id, uint32_t& sa, uint16_t& sp, uint32_t& da, uint16_t& dp);

extern void udp_server_init(boost::asio::io_context& io_context, unsigned short port_);
extern void udp_server_async_recv(std::function<void(uint32_t, std::shared_ptr<std::string>)> handler);
extern void udp_server_add_data(uint32_t relation_id, const std::string& data, std::string from_address, unsigned short from_port);
extern bool udp_server_get_original_relation(uint32_t relation_id, uint32_t& sa, uint16_t& sp, uint32_t& da, uint16_t& dp);

extern bool filter_get_process_name_from_packet(
    uint32_t sa, uint16_t sp, uint32_t da, uint16_t dp,
    std::string& name
);


struct relation_t {
    uint32_t id;
    std::string protocol;
    uint32_t relation_id;

    uint32_t original_src_addr;
    uint16_t original_src_port;
    uint32_t original_dst_addr;
    uint16_t original_dst_port;

    std::string process_name = "";
};

class any_server {
public:
    any_server(boost::asio::io_context& io_context, unsigned short tcp_port, unsigned short udp_port);
    void async_recv(std::function<void(uint32_t, std::shared_ptr<std::string>, std::string)> handler);
    void add_data(uint32_t any_server_id, const std::string& data, std::string protocol, std::string from_address = "", unsigned short from_port = 0);
    uint32_t get_id_by_relation(uint32_t relation_id, std::string protocol);
    bool get_original_relation(
        uint32_t id, std::string proto, std::string& process_name,
        uint32_t& sa, uint16_t& sp, uint32_t& da, uint16_t& dp
    );

private:
    std::function<void(uint32_t, std::shared_ptr<std::string>, std::string)> recv_handler_;
    std::unordered_map<uint32_t, relation_t> relation_map_;
    std::unordered_map<uint32_t, std::string> in_relation_map_;
    uint32_t next_id_ = 1;
    uint32_t get_new_id();
    
    void add_relation(uint32_t id, uint32_t relation_id, std::string protocol);
    void handle_tcp_recv(uint32_t relation_id, std::shared_ptr<std::string> data);
    void handle_udp_recv(uint32_t relation_id, std::shared_ptr<std::string> data);
};

any_server::any_server(boost::asio::io_context& io_context, unsigned short tcp_port, unsigned short udp_port) {
    tcp_server_init(io_context, tcp_port);
    udp_server_init(io_context, udp_port);
    tcp_server_async_recv([this](uint32_t relation_id, std::shared_ptr<std::string> data) {
        handle_tcp_recv(relation_id, data);
        });

    udp_server_async_recv([this](uint32_t relation_id, std::shared_ptr<std::string> data) {
        handle_udp_recv(relation_id, data);
        });
}

uint32_t any_server::get_new_id() {
    return next_id_++;
}

void any_server::async_recv(std::function<void(uint32_t, std::shared_ptr<std::string>, std::string)> handler) {
    recv_handler_ = handler;
}

void any_server::add_data(uint32_t any_server_id, const std::string& data, std::string protocol, std::string from_address, unsigned short from_port) {
    auto it = relation_map_.find(any_server_id);
    if (it != relation_map_.end()) {
        if (it->second.protocol == protocol) {
            if (protocol == "tcp") {
                tcp_server_add_data(it->second.relation_id, data);
            }
            else if (protocol == "udp") {
                udp_server_add_data(it->second.relation_id, data, from_address, from_port);
            }
        }
        else {
            // Lidar com o caso em que o protocolo não bate
            std::cerr << "Protocolo não bate para o ID " << any_server_id << std::endl;
        }
    }
    else {
        // Lidar com o caso em que o ID não existe
        std::cerr << "ID não existe " << any_server_id << std::endl;
    }
}

uint32_t any_server::get_id_by_relation(uint32_t relation_id, std::string protocol) {
    for (auto& relation : relation_map_) {
        if (relation.second.relation_id == relation_id && relation.second.protocol == protocol) {
            return relation.first;
        }
    }
    return -1;
}

void any_server::add_relation(uint32_t id, uint32_t relation_id, std::string protocol) {
    relation_t relation;
    relation.id = id;
    relation.protocol = protocol;
    relation.relation_id = relation_id;
    if (protocol == "tcp") {
        tcp_server_get_original_relation(relation_id, relation.original_src_addr,
            relation.original_src_port, relation.original_dst_addr, relation.original_dst_port);
    }
    else if (protocol == "udp") {
        udp_server_get_original_relation(relation_id, relation.original_src_addr,
            relation.original_src_port, relation.original_dst_addr, relation.original_dst_port);
    }

    filter_get_process_name_from_packet(
        relation.original_src_addr, 
        relation.original_src_port,
        relation.original_dst_addr,
        relation.original_dst_port,
        relation.process_name
    );

    relation_map_[id] = relation;
    in_relation_map_[relation_id] = protocol;
}

void any_server::handle_tcp_recv(uint32_t relation_id, std::shared_ptr<std::string> data) {
    std::cout << "\n " << __FILE__ << __FUNCTION__ << " : " << __LINE__;
    uint32_t id = get_id_by_relation(relation_id, "tcp");
    if (id == -1) {
        id = get_new_id();
        add_relation(id, relation_id, "tcp");
    }
    if (recv_handler_) {
        recv_handler_(id, data, "tcp");
    }
}

void any_server::handle_udp_recv(uint32_t relation_id, std::shared_ptr<std::string> data) {
    uint32_t id = get_id_by_relation(relation_id, "udp");
    if (id == 0) {
        id = get_new_id();
        add_relation(id, relation_id, "udp");
    }
    if (recv_handler_) {
        recv_handler_(id, data, "udp");
    }
}

bool any_server::get_original_relation(
    uint32_t id, std::string proto, std::string& process_name,
    uint32_t& sa, uint16_t& sp, uint32_t& da, uint16_t& dp
) {
    auto it = relation_map_.find(id);
    if (it != relation_map_.end() && it->second.protocol == proto) {
        sa = it->second.original_src_addr;
        sp = it->second.original_src_port;
        da = it->second.original_dst_addr;
        dp = it->second.original_dst_port;
        process_name = it->second.process_name;
        return true;
    }
    return false;
}

static boost::asio::io_context* any_io_context_ptr = nullptr;
static unsigned short any_tcp_port;
static unsigned short any_udp_port;
any_server* any_server_ptr = nullptr;

void filter_any_server_init(boost::asio::io_context& io_context, unsigned short tcp_port, unsigned short udp_port) {
    any_server_ptr = new any_server(io_context, tcp_port, udp_port);
}

void filter_any_server_async_recv(std::function<void(uint32_t, std::shared_ptr<std::string>, std::string)> handler) {
    any_server_ptr->async_recv(handler);
}

void filter_any_server_add_data(uint32_t any_server_id, const std::string& data, std::string protocol, std::string from_address, unsigned short from_port) {
    any_server_ptr->add_data(any_server_id, data, protocol, from_address, from_port);
}

bool filter_any_get_original_relation(
    uint32_t id, std::string proto, std::string& process_name,
    uint32_t& sa, uint16_t& sp, uint32_t& da, uint16_t& dp
) {
    return any_server_ptr->get_original_relation(
        id, proto, process_name,
        sa, sp, da, dp
    );
}