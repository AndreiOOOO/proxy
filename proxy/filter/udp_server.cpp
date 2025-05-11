
#include <boost/asio.hpp>
#include <memory>
#include <unordered_map>
#include <functional>
#include <queue>

class udp_server {
public:
    static udp_server& get_instance(boost::asio::io_context& io_context, unsigned short port) {
        static udp_server instance(io_context, port);
        return instance;
    }

    void async_recv_internal(std::function<void(uint32_t, std::shared_ptr<std::string>)> handler);
    void add_data_internal(uint32_t relation_id, const std::string& data);

private:
    udp_server(boost::asio::io_context& io_context, unsigned short port);
    boost::asio::io_context& io_context_;
    boost::asio::ip::udp::socket socket_;
    boost::asio::ip::udp::endpoint sender_endpoint_;
    std::vector<char> buffer_;
    std::function<void(uint32_t, std::shared_ptr<std::string>)> recv_handler_;

    void start_receive();
    void handle_receive(const boost::system::error_code& error, size_t bytes_transferred);
};

udp_server::udp_server(boost::asio::io_context & io_context, unsigned short port)
    : io_context_(io_context), socket_(io_context, boost::asio::ip::udp::endpoint(boost::asio::ip::udp::v4(), port)) {
    buffer_.resize(65536);
    start_receive();
}

void udp_server::async_recv_internal(std::function<void(uint32_t, std::shared_ptr<std::string>)> handler) {
    recv_handler_ = handler;
}

void udp_server::add_data_internal(uint32_t relation_id, const std::string & data) {
    boost::asio::ip::udp::endpoint endpoint = sender_endpoint_;
    socket_.async_send_to(boost::asio::buffer(data), endpoint, [](const boost::system::error_code& error, size_t bytes_transferred) {
        // Lidar com erros ou sucesso
        });
}

void udp_server::start_receive() {
    socket_.async_receive_from(boost::asio::buffer(buffer_), sender_endpoint_, std::bind(&udp_server::handle_receive, this, std::placeholders::_1, std::placeholders::_2));
}

void udp_server::handle_receive(const boost::system::error_code & error, size_t bytes_transferred) {
    if (!error) {
        if (recv_handler_) {
            std::shared_ptr<std::string> data = std::make_shared<std::string>(buffer_.data(), bytes_transferred);
            recv_handler_(0, data);
        }
        start_receive();
    }
    else {
        // Lidar com erros
    }
}

static boost::asio::io_context* io_context_ptr = nullptr;
static unsigned short port;

void udp_server_init(boost::asio::io_context & io_context, unsigned short port_) {
    io_context_ptr = &io_context;
    port = port_;
    udp_server::get_instance(io_context, port_);
}

void udp_server_async_recv(std::function<void(uint32_t, std::shared_ptr<std::string>)> handler) {
    udp_server::get_instance(*io_context_ptr, port).async_recv_internal(handler);
}

void udp_server_add_data(uint32_t relation_id, const std::string & data) {
    udp_server::get_instance(*io_context_ptr, port).add_data_internal(relation_id, data);
}

void udp_server_add_data(uint32_t relation_id, const std::string& data, std::string from_address, unsigned short from_port) {

}

bool udp_server_get_original_relation(uint32_t relation_id, uint32_t& sa, uint16_t& sp, uint32_t& da, uint16_t& dp) {
    return false;
}