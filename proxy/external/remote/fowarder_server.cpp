#include <iostream>
#include <string>
#include <memory>
#include <functional>
#include <map>
#include <vector>
#include <boost/asio.hpp>

struct packet_header {
    uint16_t packet_len;
    uint32_t sequence_id;
    uint32_t connection_id;
    uint8_t protocol;
    uint32_t gateway_id;
    uint32_t remote_address;
    uint16_t remote_port;
};

extern void gateway_remote_init(boost::asio::io_context* io_context, unsigned short port, const std::string& address = "");
extern void gateway_set_receive_callback(std::function<void(const std::string&, unsigned short, std::shared_ptr<std::string>)> handler);
extern void gateway_add_data(const std::string& ip, unsigned short port, std::shared_ptr<std::string> data);
extern void gateway_set_on_close(std::function<void(const std::string&, unsigned short)> handler);

class fowarder_remote {
public:
    fowarder_remote(boost::asio::io_context* io_context, unsigned short port) {
        gateway_remote_init(io_context, port, "");
        gateway_set_receive_callback([this](const std::string& ip, unsigned short port, std::shared_ptr<std::string> data) {
            handle_receive(ip, port, data);
            });
        gateway_set_on_close([this](std::string address, unsigned short port) {
            uint32_t gateway_id = generate_gateway_id(address, port);
            gateway_on_close(gateway_id);
            });
    }

    void send_packet(uint32_t gateway_id, uint32_t connection_id, uint8_t protocol, uint32_t remote_address, uint16_t remote_port, std::shared_ptr<std::string> data) {
        auto address = get_address_from_gateway_id(gateway_id);
        packet_header header = create_packet_header(gateway_id, connection_id, protocol, remote_address, remote_port, data->size());
        std::string packet = serialize_packet(header, data);
        gateway_add_data(address.first, address.second, std::make_shared<std::string>(packet));
    }

    packet_header create_packet_header(uint32_t gateway_id, uint32_t connection_id, uint8_t protocol, uint32_t remote_address, uint16_t remote_port, size_t data_size) {
        packet_header header;
        header.packet_len = (uint16_t)data_size;
        header.sequence_id = gateway_sequence_[gateway_id]++;
        header.connection_id = connection_id;
        header.protocol = protocol;
        header.gateway_id = gateway_id;
        header.remote_address = remote_address;
        header.remote_port = remote_port;
        return header;
    }

    std::string serialize_packet(const packet_header& header, std::shared_ptr<std::string> data) {
        std::string packet;
        packet.resize(sizeof(packet_header) + data->size());
        memcpy(&packet[0], &header, sizeof(packet_header));
        memcpy(&packet[sizeof(packet_header)], data->c_str(), data->size());
        return packet;
    }

    void set_receive_handler(std::function<void(uint32_t, uint32_t, uint8_t, uint32_t, uint16_t, std::shared_ptr<std::string>)> handler) {
        receive_handler_ = handler;
    }

private:
    void handle_receive(const std::string& ip, unsigned short port, std::shared_ptr<std::string> data) {
        uint32_t gateway_id = generate_gateway_id(ip, port);
        gateway_id_map_[gateway_id] = std::make_pair(ip, port);
        reassembler_[gateway_id].add_data(data);
        process_packets(gateway_id);
    }

    void process_packets(uint32_t gateway_id) {
        while (reassembler_[gateway_id].has_data()) {
            std::string packet = reassembler_[gateway_id].get_data();
            packet_header* header = reinterpret_cast<packet_header*>(const_cast<char*>(packet.c_str()));
            handle_packet(gateway_id, header, packet);
        }
    }

    void handle_packet(uint32_t gateway_id, packet_header* header, std::string packet) {
        if (receive_handler_) {
            receive_handler_(gateway_id, header->connection_id, header->protocol, header->remote_address, header->remote_port, std::make_shared<std::string>(packet.substr(sizeof(packet_header))));
        }
    }

    void gateway_on_close(uint32_t gateway_id) {
        reassembler_.erase(gateway_id);
        gateway_sequence_.erase(gateway_id);
        gateway_id_map_.erase(gateway_id);
    }

    uint32_t generate_gateway_id(const std::string& ip, unsigned short port) {
        return static_cast<uint32_t>(port);
    }

    std::pair<std::string, unsigned short> get_address_from_gateway_id(uint32_t gateway_id) {
        auto it = gateway_id_map_.find(gateway_id);
        if (it != gateway_id_map_.end()) {
            return it->second;
        }
        return std::make_pair("", 0);
    }

    struct reassembler {
        void add_data(std::shared_ptr<std::string> data) {
            buffer.insert(buffer.end(), data->begin(), data->end());
            try_reassemble();
        }

        void try_reassemble() {
            while (buffer.size() >= sizeof(packet_header)) {
                packet_header* header = reinterpret_cast<packet_header*>(const_cast<char*>(&buffer[0]));
                if (header->packet_len > buffer.size() - sizeof(packet_header)) {
                    break;
                }
                if (header->sequence_id != expected_sequence_id) {
                    error = true;
                    return;
                }
                expected_sequence_id++;
                complete_packets.push_back(std::make_shared<std::string>(buffer.begin(), buffer.begin() + sizeof(packet_header) + header->packet_len));
                buffer.erase(buffer.begin(), buffer.begin() + sizeof(packet_header) + header->packet_len);
            }
        }

        bool has_data() {
            return !complete_packets.empty();
        }

        std::string get_data() {
            if (!complete_packets.empty()) {
                auto data = *complete_packets.begin();
                complete_packets.erase(complete_packets.begin());
                return *data.get();
            }
            return "";
        }

        bool has_error() {
            return error;
        }

        std::vector<char> buffer;
        std::vector<std::shared_ptr<std::string>> complete_packets;
        uint32_t expected_sequence_id = 0;
        bool error = false;
    };

    std::map<uint32_t, reassembler> reassembler_;
    std::map<uint32_t, uint32_t> gateway_sequence_;
    std::map<uint32_t, std::pair<std::string, unsigned short>> gateway_id_map_;
    std::function<void(uint32_t, uint32_t, uint8_t, uint32_t, uint16_t, std::shared_ptr<std::string>)> receive_handler_;
};

fowarder_remote* fr = nullptr;

void fowarder_remote_init(boost::asio::io_context* io_context, unsigned short port) {
    fr = new fowarder_remote(io_context, port);
}

void fowarder_remote_send_packet(uint32_t gateway_id, uint32_t connection_id, uint8_t protocol, uint32_t remote_address, uint16_t remote_port, std::shared_ptr<std::string> data) {
    if (fr) {
        fr->send_packet(gateway_id, connection_id, protocol, remote_address, remote_port, data);
    }
}

void fowarder_remote_set_receive(std::function<void(uint32_t, uint32_t, uint8_t, uint32_t, uint16_t, std::shared_ptr<std::string>)> handler) {
    if (fr) {
        fr->set_receive_handler(handler);
    }
}