// Wire-level Streamable HTTP acceptance test. It deliberately loads the build
// artifact by absolute path and starts DuckDB with -init /dev/null.
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstdlib>
#include <cstdio>
#include <chrono>
#include <map>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using std::string;
using Headers = std::map<string, string>;
static int port;
static int assertions;

static void Check(bool value, const string &message) {
	assertions++;
	if (!value) throw std::runtime_error(message);
}

struct Socket {
	int fd;
	Socket() : fd(socket(AF_INET, SOCK_STREAM, 0)) {
		if (fd < 0) throw std::runtime_error("socket");
		timeval timeout {5, 0};
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
	}
	~Socket() { if (fd >= 0) close(fd); }
	void Connect() {
		sockaddr_in address {};
		address.sin_family = AF_INET;
		address.sin_port = htons(port);
		inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
		if (connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address))) throw std::runtime_error("connect");
	}
};

static string Request(const string &body, Headers headers = {}, const string &method = "POST") {
	Socket socket;
	socket.Connect();
	if (!headers.count("Content-Type")) headers["Content-Type"] = "application/json";
	if (!headers.count("Accept")) headers["Accept"] = "application/json, text/event-stream";
	string request = method + " /mcp HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n";
	for (const auto &header : headers) request += header.first + ": " + header.second + "\r\n";
	request += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
	for (size_t offset = 0; offset < request.size();) {
		auto sent = send(socket.fd, request.data() + offset, request.size() - offset, 0);
		if (sent <= 0) throw std::runtime_error("send");
		offset += sent;
	}
	string response;
	char buffer[4096];
	ssize_t received;
	while ((received = recv(socket.fd, buffer, sizeof(buffer), 0)) > 0) response.append(buffer, received);
	if (received < 0) throw std::runtime_error("receive");
	return response;
}

static void Expect(const string &reply, int status, int code) {
	Check(reply.find(" " + std::to_string(status) + " ") != string::npos, reply);
	Check(reply.find("\"code\":" + std::to_string(code)) != string::npos, reply);
}

static string Modern(const string &method = "server/discover", Headers headers = {}) {
	if (!headers.count("MCP-Protocol-Version")) headers["MCP-Protocol-Version"] = "2026-07-28";
	if (!headers.count("Mcp-Method")) headers["Mcp-Method"] = method;
	return Request(R"({"jsonrpc":"2.0","id":1,"method":")" + method +
	               R"(","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":")" +
	               headers["MCP-Protocol-Version"] +
	               R"(","io.modelcontextprotocol/clientCapabilities":{}}}})", headers);
}

int main() {
	signal(SIGPIPE, SIG_IGN);
	const char *duckdb = std::getenv("DUCKDB");
	const char *extension = std::getenv("MCP_EXTENSION");
	if (!duckdb || !extension || extension[0] != '/') return 2;
	Socket reservation;
	sockaddr_in address {};
	address.sin_family = AF_INET;
	address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	if (bind(reservation.fd, reinterpret_cast<sockaddr *>(&address), sizeof(address))) return 2;
	socklen_t length = sizeof(address);
	getsockname(reservation.fd, reinterpret_cast<sockaddr *>(&address), &length);
	port = ntohs(address.sin_port);
	close(reservation.fd);
	reservation.fd = -1;
	pid_t pid = fork();
	if (pid == 0) {
		string sql = "LOAD '" + string(extension) + "'; SELECT mcp_server_start('http','127.0.0.1'," +
		             std::to_string(port) + ",' {\"background\":false,\"max_connections\":8,"
		             "\"max_request_bytes\":4096,\"max_response_bytes\":8192,\"http_io_timeout_seconds\":1}');";
		execl(duckdb, duckdb, "-unsigned", "-init", "/dev/null", "-bail", ":memory:", "-c", sql.c_str(),
		      static_cast<char *>(nullptr));
		_exit(127);
	}
	try {
		for (int i = 0; i < 50; i++) {
			try { if (Request("", {}, "GET").find(" 405 ") != string::npos) break; } catch (...) {}
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
		auto discover = Modern();
		Check(discover.find(" 200 ") != string::npos, "discover");
		Check(discover.find("supportedVersions") != string::npos &&
		          discover.find("io.modelcontextprotocol/serverInfo") != string::npos,
		      "discovery metadata shape");
		Expect(Request("{"), 400, -32700);
		Expect(Request("[]"), 400, -32600);
		Expect(Modern("server/discover", {{"Mcp-Method", "tools/list"}}), 400, -32020);
		Expect(Modern("server/discover", {{"MCP-Protocol-Version", "2099-01-01"}}), 400, -32022);
		Expect(Request("{}", {{"Origin", "https://attacker.example"}}), 403, -32003);
		Check(Modern("server/discover", {{"Origin", "http://localhost:3000"}}).find(" 200 ") != string::npos,
		      "loopback origin");
		Check(Request("", {}, "GET").find(" 405 ") != string::npos, "GET rejected");
		Check(Request(string(5000, ' ')).find(" 413 ") != string::npos, "request cap");
		Expect(Request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/call\",\"params\":{"
		               "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"2026-07-28\","
		               "\"io.modelcontextprotocol/clientCapabilities\":{}},\"name\":\"query\",\"arguments\":{"
		               "\"sql\":\"SELECT repeat('x', 20000)\"}}}",
		              {{"MCP-Protocol-Version", "2026-07-28"}, {"Mcp-Method", "tools/call"},
		               {"Mcp-Name", "query"}}),
		       500, -32000);
		std::vector<std::thread> clients;
		for (int i = 0; i < 8; i++) clients.emplace_back([] { (void)Modern("tools/list"); });
		for (auto &client : clients) client.join();
		kill(pid, SIGTERM);
		waitpid(pid, nullptr, 0);
		return assertions ? 0 : 1;
	} catch (const std::exception &error) {
		fprintf(stderr, "transport regression: %s\n", error.what());
		kill(pid, SIGTERM);
		waitpid(pid, nullptr, 0);
		return 1;
	}
}
