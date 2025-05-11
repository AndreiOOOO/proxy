#include <boost/asio.hpp>
#include <memory>
#include <unordered_map>
#include <functional>
#include <queue>

extern bool  filter_get_original_relation_info(uint32_t da, uint16_t dp, uint32_t& original_sa, uint16_t& original_sp, uint32_t& original_da, uint16_t& original_dp);

class tcp_server {
public:
    static tcp_server& get_instance(boost::asio::io_context& io_context, unsigned short port) {
        static tcp_server instance(io_context, port);
        return instance;
    }

    void async_recv_internal(std::function<void(uint32_t, std::shared_ptr<std::string>)> handler);
    void add_data_internal(uint32_t relation_id, const std::string& data);
    bool get_original_relation(uint32_t relation_id, uint32_t& sa, uint16_t& sp, uint32_t& da, uint16_t& dp);

private:
    tcp_server(boost::asio::io_context& io_context, unsigned short port);
    boost::asio::io_context& io_context_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::unordered_map<uint32_t, std::shared_ptr<boost::asio::ip::tcp::socket>> connections_;
    std::unordered_map<uint32_t, std::vector<char>> buffers_;
    std::unordered_map<uint32_t, std::queue<std::string>> write_queues_;
    std::unordered_map<uint32_t, bool> writing_;
    uint32_t next_id_ = 0;
    std::function<void(uint32_t, std::shared_ptr<std::string>)> recv_handler_;
    void start_accept();
    void handle_accept(std::shared_ptr<boost::asio::ip::tcp::socket> socket, const boost::system::error_code& error);
    void handle_read(uint32_t relation_id, std::shared_ptr<boost::asio::ip::tcp::socket> socket, const boost::system::error_code& error, size_t bytes_transferred);
    void write_next(uint32_t relation_id);
};

tcp_server::tcp_server(boost::asio::io_context& io_context, unsigned short port)
    : io_context_(io_context), acceptor_(io_context, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), port)) {
    start_accept();
}

void tcp_server::async_recv_internal(std::function<void(uint32_t, std::shared_ptr<std::string>)> handler) {
    recv_handler_ = handler;
}

void tcp_server::add_data_internal(uint32_t relation_id, const std::string& data) {
    auto it = connections_.find(relation_id);
    if (it != connections_.end()) {
        write_queues_[relation_id].push(data);
        if (!writing_[relation_id]) {
            writing_[relation_id] = true;
            write_next(relation_id);
        }
    }
}

bool tcp_server::get_original_relation(uint32_t relation_id, uint32_t& sa, uint16_t& sp, uint32_t& da, uint16_t& dp) {
    auto it = connections_.find(relation_id);
    if (it != connections_.end()) {
        boost::asio::ip::tcp::endpoint endpoint = it->second->remote_endpoint();
        uint32_t current_sa = endpoint.address().to_v4().to_ulong();
        uint16_t current_sp = endpoint.port();
        uint32_t current_da = acceptor_.local_endpoint().address().to_v4().to_ulong();
        uint16_t current_dp = acceptor_.local_endpoint().port();
        
        uint32_t original_sa, original_da;
        uint16_t original_sp, original_dp;

        bool res = filter_get_original_relation_info(current_da, current_dp, original_sa, original_sp, original_da, original_dp);
        if (res) {
            sa = original_sa;
            sp = original_sp;
            da = original_da;
            dp = original_dp;
            return true;
        }
    }
    return false;
}



void tcp_server::start_accept() {
    std::shared_ptr<boost::asio::ip::tcp::socket> socket = std::make_shared<boost::asio::ip::tcp::socket>(io_context_);
    acceptor_.async_accept(*socket, std::bind(&tcp_server::handle_accept, this, socket, std::placeholders::_1));
}

void tcp_server::handle_accept(std::shared_ptr<boost::asio::ip::tcp::socket> socket, const boost::system::error_code& error) {
    if (!error) {
        uint32_t relation_id = next_id_++;
        connections_[relation_id] = socket;
        buffers_[relation_id].resize(60000);
        socket->async_read_some(boost::asio::buffer(buffers_[relation_id]), std::bind(&tcp_server::handle_read, this, relation_id, socket, std::placeholders::_1, std::placeholders::_2));
    }
    start_accept();
}

void tcp_server::handle_read(uint32_t relation_id, std::shared_ptr<boost::asio::ip::tcp::socket> socket, const boost::system::error_code& error, size_t bytes_transferred) {
    if (!error) {
        if (recv_handler_) {
            std::shared_ptr<std::string> data = std::make_shared<std::string>(buffers_[relation_id].data(), bytes_transferred);
            io_context_.post([relation_id, data, this]() { recv_handler_(relation_id, data); });
        }
        socket->async_read_some(boost::asio::buffer(buffers_[relation_id]), std::bind(&tcp_server::handle_read, this, relation_id, socket, std::placeholders::_1, std::placeholders::_2));
    }
    else {
        io_context_.post([relation_id, this]() { connections_.erase(relation_id); buffers_.erase(relation_id); write_queues_.erase(relation_id); writing_.erase(relation_id); });
    }
}

void tcp_server::write_next(uint32_t relation_id) {
    if (!write_queues_[relation_id].empty()) {
        std::string data = write_queues_[relation_id].front();
        write_queues_[relation_id].pop();
        boost::asio::async_write(*connections_[relation_id], boost::asio::buffer(data), [relation_id, this](const boost::system::error_code& error, size_t bytes_transferred) {
            if (error) {
                io_context_.post([relation_id, this]() { connections_.erase(relation_id); buffers_.erase(relation_id); write_queues_.erase(relation_id); writing_.erase(relation_id); });
            }
            else {
                write_next(relation_id);
            }
            });
    }
    else {
        writing_[relation_id] = false;
    }
}

static boost::asio::io_context* io_context_ptr = nullptr;
static unsigned short port;

void tcp_server_init(boost::asio::io_context& io_context, unsigned short port_) {
    io_context_ptr = &io_context;
    port = port_;
    tcp_server::get_instance(io_context, port_);
}

void tcp_server_async_recv(std::function<void(uint32_t, std::shared_ptr<std::string>)> handler) {
    tcp_server::get_instance(*io_context_ptr, port).async_recv_internal(handler);
}

void tcp_server_add_data(uint32_t relation_id, const std::string& data) {
    tcp_server::get_instance(*io_context_ptr, port).add_data_internal(relation_id, data);
}

bool tcp_server_get_original_relation(uint32_t relation_id, uint32_t & sa, uint16_t & sp, uint32_t & da, uint16_t & dp) {
    return tcp_server::get_instance(*io_context_ptr, port).get_original_relation(relation_id, sa, sp, da, dp);
}
