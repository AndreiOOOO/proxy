#include <boost/asio.hpp>
#include <memory>
#include <functional>
#include <unordered_map>
#include <string>

extern void tcp_server_init(boost::asio::io_context& io_context, unsigned short port);
extern void tcp_server_async_recv(std::function<void(uint32_t, std::shared_ptr<std::string>)> handler);
extern void tcp_server_add_data(uint32_t relation_id, const std::string& data);
extern bool tcp_server_get_original_relation(uint32_t relation_id, uint32_t& sa, uint16_t& sp, uint32_t& da, uint16_t& dp);

extern void udp_server_init(boost::asio::io_context& io_context, unsigned short port);
extern void udp_server_async_recv(std::function<void(uint32_t, std::shared_ptr<std::string>)> handler);
extern void udp_server_add_data(uint32_t relation_id, const std::string& data, std::string from_address, unsigned short from_port);
extern bool udp_server_get_original_relation(uint32_t relation_id, uint32_t& sa, uint16_t& sp, uint32_t& da, uint16_t& dp);

class any_server {
public:
    any_server(boost::asio::io_context& io_context, unsigned short tcp_port, unsigned short udp_port);
    void async_recv(std::function<void(uint32_t, std::shared_ptr<std::string>, std::string)> handler);
    void add_data(uint32_t any_server_id, const std::string& data, std::string protocol, std::string from_address = "", unsigned short from_port = 0);
    bool get_original_relation_id(uint32_t id, std::string proto, uint32_t& relation_id);

private:
    std::function<void(uint32_t, std::shared_ptr<std::string>, std::string)> recv_handler_;
    std::unordered_map<uint32_t, std::pair<uint32_t, std::string>> tcp_id_map_;
    std::unordered_map<uint32_t, std::pair<uint32_t, std::pair<std::string, unsigned short>>> udp_id_map_;
    uint32_t next_id_ = 1;
    uint32_t get_new_id();
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
    if (protocol == "tcp") {
        auto it = tcp_id_map_.find(any_server_id);
        if (it != tcp_id_map_.end()) {
            tcp_server_add_data(it->second.first, data);
        }
    }
    else if (protocol == "udp") {
        auto it = udp_id_map_.find(any_server_id);
        if (it != udp_id_map_.end()) {
            udp_server_add_data(it->second.first, data, from_address, from_port);
        }
    }
}

bool any_server::get_original_relation_id(uint32_t id, std::string proto, uint32_t& relation_id) {
    if (proto == "tcp") {
        auto it = tcp_id_map_.find(id);
        if (it != tcp_id_map_.end()) {
            relation_id = it->second.first;
            return true;
        }
    }
    else if (proto == "udp") {
        auto it = udp_id_map_.find(id);
        if (it != udp_id_map_.end()) {
            relation_id = it->second.first;
            return true;
        }
    }
    return false;
}

void any_server::handle_tcp_recv(uint32_t relation_id, std::shared_ptr<std::string> data) {
    uint32_t new_id = get_new_id();
    tcp_id_map_[new_id] = std::make_pair(relation_id, "tcp");
    if (recv_handler_) {
        recv_handler_(new_id, data, "tcp");
    }
}

void any_server::handle_udp_recv(uint32_t relation_id, std::shared_ptr<std::string> data) {
    uint32_t new_id = get_new_id();
    udp_id_map_[new_id] = std::make_pair(relation_id, std::make_pair("", 0));
    if (recv_handler_) {
        recv_handler_(new_id, data, "udp");
    }
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

bool filter_any_get_original_relation(uint32_t id, std::string proto, uint32_t& sa, uint16_t& sp, uint32_t& da, uint16_t& dp) {
    uint32_t relation_id;
    if (any_server_ptr->get_original_relation_id(id, proto, relation_id)) {
        if (proto == "tcp") {
            return tcp_server_get_original_relation(relation_id, sa, sp, da, dp);
        }
        else if (proto == "udp") {
            return udp_server_get_original_relation(relation_id, sa, sp, da, dp);
        }
    }
    return false;
}
