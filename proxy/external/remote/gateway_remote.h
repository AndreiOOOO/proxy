#include <boost/asio.hpp>
#include <memory>
#include <functional>
#include <map>
#include <string>
#include <queue>
// ServerSession.h

class ServerSession {
public:
    ServerSession(boost::asio::io_context& io_context, boost::asio::ip::tcp::socket socket);
    ~ServerSession();

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


class Server {
public:
    Server(boost::asio::io_context& io_context, unsigned short port);
    ~Server();

    void start_accept();
    void async_recv(int session_id, std::function<void(int, std::shared_ptr<std::string>)> handler);
    void add_data(int session_id, std::shared_ptr<std::string> data);
    void close_session(int session_id);

private:
    boost::asio::io_context& io_context_;
    boost::asio::ip::tcp::acceptor acceptor_;
    std::map<int, std::shared_ptr<ServerSession>> sessions_;
    int next_session_id_ = 0;

    void handle_accept(std::shared_ptr<ServerSession> session, const boost::system::error_code& error);
};

