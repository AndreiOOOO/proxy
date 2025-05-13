#pragma once

#include <boost/asio.hpp>
#include <memory>
#include <unordered_map>
#include <functional>
#include <queue>
#include <map>

extern void filter_any_server_async_recv(std::function<void(uint32_t, std::shared_ptr<std::string>, std::string)> handler);
extern void filter_any_server_add_data(uint32_t any_server_id, const std::string& data, std::string protocol, std::string from_address, unsigned short from_port);
extern bool filter_any_get_original_relation(uint32_t id, std::string proto, std::string& pname, uint32_t& sa, uint16_t& sp, uint32_t& da, uint16_t& dp);

//internet connector test local
extern void internet_connector_async_send(
    uint32_t id, uint8_t proto, uint32_t dest_address,
    uint16_t dest_port, std::shared_ptr<std::string> data);
extern void internet_connector_async_receive(
    std::function<void(uint32_t con_id, std::shared_ptr<std::string>)> handler);

//fowarder
extern void fowarder_send_packet(uint32_t gateway_id, uint32_t connection_id, uint8_t protocol,
    uint32_t remote_address, uint16_t remote_port, std::shared_ptr<std::string> data);
extern void fowarder_set_recv_handler(
    std::function<void(uint32_t, uint32_t, uint32_t, uint16_t, std::shared_ptr<std::string>)> handler);
extern void fowarder_set_gateway_recv(uint32_t gateway_id);


//gateway
extern uint32_t gateway_new_gateway(uint32_t id);
extern void gateway_set_remote_endpoint(uint32_t id, uint32_t ip, uint16_t port);
