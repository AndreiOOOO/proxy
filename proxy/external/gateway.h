#include <boost/asio.hpp>
#include <memory>
#include <functional>
#include <map>
#include <string>
#include <queue>

const uint16_t MAX_BUFFER_SIZE = -1;
// ClientGateway.h

class ClientSession;

class ClientGateway {
public:
    ClientGateway(boost::asio::io_context& io_context);
    ~ClientGateway();

    void connect(const std::string& host, unsigned short port);
    void async_recv(std::function<void(int, std::shared_ptr<std::string>)> handler);
    void add_data(std::shared_ptr<std::string> data);
    void close();

private:
    boost::asio::io_context& io_context_;
    std::shared_ptr<ClientSession> session_;
    int session_id_ = 0;

    void handle_connect(const boost::system::error_code& error);
};

// ClientSession.h
class ClientSession {
public:
    ClientSession(boost::asio::io_context& io_context, boost::asio::ip::tcp::socket socket);
    ~ClientSession();

    void start();
    void async_recv(std::function<void(std::shared_ptr<std::string>)> handler);
    void add_data(std::shared_ptr<std::string> data);
    void close();

private:
    boost::asio::io_context& io_context_;
    boost::asio::ip::tcp::socket socket_;
    std::vector<char> buffer_;
    std::function<void(std::shared_ptr<std::string>)> recv_handler_;
    std::queue<std::shared_ptr<std::string>> write_queue_;
    bool writing_ = false;

    void handle_read(const boost::system::error_code& error, size_t bytes_transferred);
    void write_next();
    void handle_write(const boost::system::error_code& error);
};

