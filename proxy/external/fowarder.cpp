#include <iostream>
#include <string>
#include <memory>
#include <functional>
#include <cstring>
#include <map>
#include <vector>

struct packet_header {
    uint16_t packet_len;
    uint32_t sequence_id;
    uint32_t connection_id;
    uint8_t protocol;
    uint32_t gateway_id;
    uint32_t remote_address;
    uint16_t remote_port;
};

extern void gateway_add_data(uint32_t id, std::shared_ptr<std::string> data);
extern void gateway_async_recv(
    uint32_t gateway_id,
    std::function<void(uint32_t gateway_id, std::shared_ptr<std::string>)> handler
);
extern void gateway_set_on_restart(
    uint32_t gateway_id,
    std::function<void(uint32_t gateway_id)> handler
);

class packet_reassembler {
public:
    void add_data(uint32_t gateway_id, std::shared_ptr<std::string> packet) {
        if (gateway_sequences_.find(gateway_id) == gateway_sequences_.end()) {
            gateway_sequences_[gateway_id] = sequence_tracker(gateway_id);
        }

        gateway_sequences_[gateway_id].add_packet(packet);
    }

    bool has_data(uint32_t gateway_id) {
        if (gateway_sequences_.find(gateway_id) != gateway_sequences_.end()) {
            return gateway_sequences_[gateway_id].has_data();
        }
        return false;
    }

    std::string get_data(uint32_t gateway_id) {
        if (gateway_sequences_.find(gateway_id) != gateway_sequences_.end()) {
            return gateway_sequences_[gateway_id].get_data();
        }
        return "";
    }

    bool has_error(uint32_t gateway_id) {
        if (gateway_sequences_.find(gateway_id) != gateway_sequences_.end()) {
            return gateway_sequences_[gateway_id].has_error();
        }
        return false;
    }

    void reset(uint32_t gateway_id) {
        if (gateway_sequences_.find(gateway_id) != gateway_sequences_.end()) {
            gateway_sequences_.erase(gateway_id);
        }
    }

private:
    struct sequence_tracker {
        sequence_tracker() : gateway_id(0), expected_sequence_id(0) {}
        sequence_tracker(uint32_t gateway_id) : gateway_id(gateway_id), expected_sequence_id(0) {}

        void add_packet(std::shared_ptr<std::string> packet) {
            buffer.insert(buffer.end(), packet->begin(), packet->end());
            try_reassemble();
        }

        void try_reassemble() {
            while (buffer.size() >= sizeof(packet_header)) {
                packet_header* header = reinterpret_cast<packet_header*>(const_cast<char*>(&buffer[0]));

                if (header->sequence_id != expected_sequence_id) {
                    error = true;
                    return;
                }

                if (buffer.size() < sizeof(packet_header) + header->packet_len) {
                    break;
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

        uint32_t gateway_id;
        uint32_t expected_sequence_id;
        std::vector<char> buffer;
        std::vector<std::shared_ptr<std::string>> complete_packets;
        bool error = false;
    };

    std::map<uint32_t, sequence_tracker> gateway_sequences_;
};

class packet_forwarder {
public:
    void add_data(
        uint32_t gateway_id, uint32_t connection_id,
        uint8_t protocol, uint32_t remote_address, uint16_t remote_port, std::shared_ptr<std::string> data) {
        packet_header header = generate_packet_header(gateway_id, connection_id, protocol, remote_address, remote_port, data);
        std::string packet = generate_packet(header, data);
        send_packet(gateway_id, packet);
    }

    void set_gateway_receive(uint32_t gateway_id) {
        auto receive_handler = [this](uint32_t gw_id, std::shared_ptr<std::string> packet) {
            handle_gateway_receive(gw_id, packet);
            };
        gateway_async_recv(gateway_id, receive_handler);

        auto reset_handler = [this](uint32_t gw_id) {
            handle_gateway_reset(gw_id);
            };
        gateway_set_on_restart(gateway_id, reset_handler);
    }

    void set_recv_handler(std::function<void(uint32_t, uint32_t, uint32_t, uint16_t, std::shared_ptr<std::string>)> handler) {
        recv_handler_ = handler;
    }

private:
    packet_header generate_packet_header(
        uint32_t gateway_id, uint32_t connection_id,
        uint8_t protocol, uint32_t remote_address, uint16_t remote_port, std::shared_ptr<std::string> data) {
        packet_header header;
        header.packet_len = (uint16_t)data->size();
        header.sequence_id = gateway_id_sequence_[gateway_id]++;
        header.connection_id = connection_id;
        header.protocol = protocol;
        header.gateway_id = gateway_id;
        header.remote_address = remote_address;
        header.remote_port = remote_port;
        return header;
    }

    std::string generate_packet(packet_header header, std::shared_ptr<std::string> data) {
        std::string packet;
        packet.resize(sizeof(packet_header) + data->size());
        memcpy(&packet[0], &header, sizeof(packet_header));
        memcpy(&packet[sizeof(packet_header)], data->c_str(), data->size());
        return packet;
    }

    void send_packet(uint32_t gateway_id, std::string packet) {
        gateway_add_data(gateway_id, std::make_shared<std::string>(packet));
    }

    void handle_gateway_receive(uint32_t gateway_id, std::shared_ptr<std::string> packet) {
        std::cout << "\n " << __FILE__ << __FUNCTION__ << " data sz " << packet->size();
        reassembler_.add_data(gateway_id, packet);
        if (reassembler_.has_error(gateway_id)) {
            reset_gateway_state(gateway_id);
            return;
        }

        while (reassembler_.has_data(gateway_id)) {
            std::string data = reassembler_.get_data(gateway_id);
            process_packet(gateway_id, data);
        }
    }

    void handle_gateway_reset(uint32_t gateway_id) {
        reset_gateway_state(gateway_id);
    }

    void reset_gateway_state(uint32_t gateway_id) {
        reassembler_.reset(gateway_id);
        gateway_id_sequence_[gateway_id] = 0; // Resetar o sequence ID
    }

    void process_packet(uint32_t gateway_id, std::string packet) {
        packet_header* header = reinterpret_cast<packet_header*>(const_cast<char*>(packet.c_str()));
        std::shared_ptr<std::string> data = std::make_shared<std::string>(packet.substr(sizeof(packet_header)));
        if (recv_handler_) {
            recv_handler_(gateway_id, header->connection_id, header->remote_address, header->remote_port, data);
        }
    }

    packet_reassembler reassembler_;
    std::map<uint32_t, uint32_t> gateway_id_sequence_;
    std::function<void(uint32_t, uint32_t, uint32_t, uint16_t, std::shared_ptr<std::string>)> recv_handler_;
};

packet_forwarder pf;

void fowarder_set_recv_handler(std::function<void(uint32_t, uint32_t, uint32_t, uint16_t, std::shared_ptr<std::string>)> handler) {
    pf.set_recv_handler(handler);
}

void fowarder_set_gateway_recv(uint32_t gateway_id) {
    pf.set_gateway_receive(gateway_id);
}

void fowarder_send_packet(uint32_t gateway_id, uint32_t connection_id, uint8_t protocol,
    uint32_t remote_address, uint16_t remote_port, std::shared_ptr<std::string> data) {
    std::cout << "\n " << __FILE__ << __FUNCTION__ << " data sz " << data->size();
    pf.add_data(gateway_id, connection_id, protocol, remote_address, remote_port, data);
}