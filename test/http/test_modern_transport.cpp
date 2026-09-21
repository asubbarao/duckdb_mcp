// Standalone wire-level acceptance harness. Compile with:
// c++ -std=c++11 -pthread test/http/test_modern_transport.cpp -o /tmp/test_modern_transport
// DUCKDB=/path/to/duckdb MCP_EXTENSION=/absolute/path/to/artifact QUACK_EXTENSION=/absolute/path/to/quack /tmp/test_modern_transport
// Always LOAD the exact artifact; never rely on an installed extension or startup file.
#include <arpa/inet.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <chrono>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <future>
#include <iostream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

using std::string;
using Headers = std::map<string, string>;
static int port;
static int assertions;

static void Check(bool condition, const string &message) {
	assertions++;
	if (!condition) {
		throw std::runtime_error(message);
	}
}

struct Socket {
	int fd;
	Socket() : fd(socket(AF_INET, SOCK_STREAM, 0)) {
		if (fd < 0) {
			throw std::runtime_error("socket failed");
		}
		timeval timeout {5, 0};
		setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
		setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
	}
	~Socket() { close(fd); }
	void Connect() {
		sockaddr_in address {};
		address.sin_family = AF_INET;
		address.sin_port = htons(port);
		inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
		if (connect(fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0) {
			throw std::runtime_error("connect failed");
		}
	}
};

static void SendAll(int fd, const string &data) {
	size_t offset = 0;
	while (offset < data.size()) {
		auto sent = send(fd, data.data() + offset, data.size() - offset, 0);
		if (sent <= 0) {
			throw std::runtime_error("send failed");
		}
		offset += sent;
	}
}

struct Reply {
	int status;
	string body;
	string headers;
};

static Reply Request(const string &body = "", Headers headers = {}, const string &method = "POST",
                     const string &path = "/mcp") {
	Socket socket;
	socket.Connect();
	if (!headers.count("Content-Type")) {
		headers["Content-Type"] = "application/json";
	}
	if (!headers.count("Accept")) {
		headers["Accept"] = "application/json, text/event-stream";
	}
	string request = method + " " + path + " HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n";
	for (const auto &header : headers) {
		request += header.first + ": " + header.second + "\r\n";
	}
	request += "Content-Length: " + std::to_string(body.size()) + "\r\n\r\n" + body;
	SendAll(socket.fd, request);
	string response;
	char buffer[4096];
	ssize_t length;
	while ((length = recv(socket.fd, buffer, sizeof(buffer), 0)) > 0) {
		response.append(buffer, length);
	}
	if (length < 0) {
		throw std::runtime_error("receive failed or timed out");
	}
	auto split = response.find("\r\n\r\n");
	if (split == string::npos) {
		throw std::runtime_error("invalid HTTP response: " + response);
	}
	return {std::stoi(response.substr(response.find(' ') + 1, 3)), response.substr(split + 4),
	        response.substr(0, split)};
}

static Reply Modern(const string &method = "server/discover", const string &params = "", Headers headers = {},
                    const string &version = "2026-07-28") {
	if (!headers.count("MCP-Protocol-Version")) {
		headers["MCP-Protocol-Version"] = version;
	}
	if (!headers.count("Mcp-Method")) {
		headers["Mcp-Method"] = method;
	}
	return Request("{\"jsonrpc\":\"2.0\",\"id\":\"probe\",\"method\":\"" + method + "\",\"params\":{"
	               "\"_meta\":{\"io.modelcontextprotocol/protocolVersion\":\"" + version + "\","
	               "\"io.modelcontextprotocol/clientCapabilities\":{},"
	               "\"io.modelcontextprotocol/clientInfo\":{\"name\":\"transport-test\",\"version\":\"1\"}}" +
	               (params.empty() ? "" : "," + params) + "}}", headers);
}

static void Error(const Reply &reply, int status, int code) {
	Check(reply.status == status, "Expected HTTP " + std::to_string(status) + ", got " +
	                             std::to_string(reply.status) + " " + reply.body);
	Check(reply.body.find("\"code\":" + std::to_string(code)) != string::npos,
	      "Expected RPC " + std::to_string(code) + ": " + reply.body);
}

static string QuoteSQL(const string &value) {
	string result = "'";
	for (char c : value) {
		result += c;
		if (c == '\'') {
			result += c;
		}
	}
	return result + "'";
}

struct Service {
	pid_t pid = -1;
	string directory;
	bool quack;
	Service(bool quack = false, bool scoped_secret = false) : quack(quack) {
		const char *duckdb = std::getenv("DUCKDB");
		const char *extension = std::getenv("MCP_EXTENSION");
		if (!duckdb || !extension || extension[0] != '/') {
			throw std::runtime_error("Set DUCKDB and absolute MCP_EXTENSION");
		}
		const char *quack_extension = std::getenv("QUACK_EXTENSION");
		if (quack && (!quack_extension || quack_extension[0] != '/')) {
			throw std::runtime_error("Set absolute QUACK_EXTENSION for scoped-secret coverage");
		}
		std::cout << "Testing exact MCP artifact: " << extension << std::endl;
		{
			Socket socket;
			sockaddr_in address {};
			address.sin_family = AF_INET;
			address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
			if (bind(socket.fd, reinterpret_cast<sockaddr *>(&address), sizeof(address)) != 0) {
				throw std::runtime_error("ephemeral bind failed");
			}
			socklen_t length = sizeof(address);
			getsockname(socket.fd, reinterpret_cast<sockaddr *>(&address), &length);
			port = ntohs(address.sin_port);
		}
		char pattern[] = "/tmp/mcp-transport-XXXXXX";
		auto temp = mkdtemp(pattern);
		if (!temp) {
			throw std::runtime_error("mkdtemp failed");
		}
		directory = temp;
		string setup;
		if (quack) {
			setup = "LOAD " + QuoteSQL(quack_extension) + "; CREATE SCHEMA workspace;";
			if (scoped_secret) {
				setup += "CREATE SECRET mcp_test (TYPE quack, TOKEN 'test-token', SCOPE 'quack:127.0.0.1:9494');";
			}
			setup += "SELECT 1 FROM quack_serve('quack:127.0.0.1:9494', token := 'test-token');";
		}
		string sql = setup + "LOAD " + QuoteSQL(extension) + "; SELECT mcp_server_start('http','127.0.0.1'," +
		             std::to_string(port) + ",'{\"background\":false,\"max_connections\":4,"
		             "\"max_request_bytes\":4096,\"max_response_bytes\":8192,\"http_io_timeout_seconds\":1,"
		             "\"enable_quack_query_tool\":true}');"
		             "SELECT 'FOREGROUND_EXITED';";
		if (quack) {
			sql += "CALL quack_stop('quack:127.0.0.1:9494');";
		}
		pid = fork();
		if (pid == 0) {
			int log = open((directory + "/server.log").c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0600);
			dup2(log, STDOUT_FILENO);
			dup2(log, STDERR_FILENO);
			close(log);
			execlp(duckdb, duckdb, "-unsigned", "-init", "/dev/null", "-bail",
			       (directory + "/test.duckdb").c_str(), "-c", sql.c_str(), static_cast<char *>(nullptr));
			_exit(127);
		}
		if (pid < 0) {
			throw std::runtime_error("fork failed");
		}
	}
	void Ready() {
		for (int i = 0; i < 150; i++) {
			int status;
			if (waitpid(pid, &status, WNOHANG) == pid) {
				pid = -1;
				std::ifstream log(directory + "/server.log");
				std::stringstream content;
				content << log.rdbuf();
				throw std::runtime_error("Service exited: " + content.str());
			}
			try {
				if (Request("", {}, "GET", "/health").status == 200) {
					return;
				}
			} catch (const std::exception &) {
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
		throw std::runtime_error("Service readiness timeout; log: " + directory + "/server.log");
	}
	void Shutdown() {
		auto reply = Modern("shutdown");
		Check(reply.status == 200, "Managed foreground shutdown response: " + reply.body);
		for (int i = 0; i < 50; i++) {
			int status;
			if (waitpid(pid, &status, WNOHANG) == pid) {
				Check(WIFEXITED(status) && WEXITSTATUS(status) == 0, "Foreground DuckDB must exit cleanly");
				pid = -1;
				return;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(100));
		}
		throw std::runtime_error("Managed foreground listener did not stop; log: " + directory + "/server.log");
	}
	~Service() {
		if (pid > 0) {
			kill(pid, SIGTERM);
			waitpid(pid, nullptr, 0);
		}
		std::cout << "Service evidence: " << directory << std::endl;
	}
};

int main() {
	signal(SIGPIPE, SIG_IGN);
	// Scoped-secret coverage must not inherit an ambient launchd credential.
	unsetenv("SYSTEM_QUACK_TOKEN");
	try {
		Service service;
		service.Ready();
		Check(Modern().status == 200, "Modern discovery");
		std::vector<std::future<Reply>> concurrent;
		for (int i = 0; i < 4; i++) {
			concurrent.emplace_back(std::async(std::launch::async, [] { return Modern("tools/list"); }));
		}
		for (auto &future : concurrent) {
			Check(future.get().status == 200, "Concurrent tools/list");
		}
		for (auto version : {"2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25"}) {
			auto reply = Request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{"
			                     "\"protocolVersion\":\"" + string(version) + "\",\"capabilities\":{},"
			                     "\"clientInfo\":{\"name\":\"legacy\",\"version\":\"1\"}}}");
			Check(reply.status == 200 && reply.body.find(version) != string::npos, "Legacy initialize: " + reply.body);
			reply = Request("{\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}",
			                {{"MCP-Protocol-Version", version}});
			Check(reply.status == 202 && reply.body.empty(), "Notification must return empty 202");
		}
		Error(Request("{"), 400, -32700);
		for (auto body : {"[]", "null", "{\"jsonrpc\":\"1.0\",\"id\":1,\"method\":\"ping\"}",
		                  "{\"jsonrpc\":\"2.0\",\"id\":true,\"method\":\"ping\"}",
		                  "{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}"}) {
			Error(Request(body), 400, -32600);
		}
		Error(Request("{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\",\"params\":[]}"), 400, -32602);
		for (const auto &headers : std::vector<Headers> {{{"MCP-Protocol-Version", ""}}, {{"Mcp-Method", ""}},
		                                                {{"Mcp-Method", "tools/list"}},
		                                                {{"MCP-Protocol-Version", "2025-11-25"}}}) {
			Error(Modern("server/discover", "", headers), 400, -32020);
		}
		auto unsupported = Modern("server/discover", "", {}, "2099-01-01");
		Error(unsupported, 400, -32022);
		Check(unsupported.body.find("supported") != string::npos &&
		      unsupported.body.find("2026-07-28") != string::npos, "Supported versions advertised");
		string query = "\"name\":\"query\",\"arguments\":{\"sql\":\"SELECT 42 AS answer\"}";
		Error(Modern("tools/call", query, {{"Mcp-Name", "wrong"}}), 400, -32020);
		Error(Modern("tools/call", query, {{"Mcp-Name", "=?base64?!!!!?="}}), 400, -32020);
		auto encoded = Modern("tools/call", query, {{"Mcp-Name", "=?base64?cXVlcnk=?="}});
		Check(encoded.status == 200 && encoded.body.find("42") != string::npos, "Base64 tool name: " + encoded.body);
		for (auto origin : {"https://attacker.example", "http://localhost.attacker.example", "null",
		                    "http://127.0.0.1@attacker.example", "http://localhost:0", ""}) {
			Check(Request("{}", {{"Origin", origin}}).status == 403, "Reject origin on MCP");
			Check(Request("", {{"Origin", origin}}, "GET", "/health").status == 403, "Reject origin on health");
			Check(Request("", {{"Origin", origin}}, "DELETE").status == 403, "Reject origin on DELETE");
		}
		for (auto origin : {"http://localhost:3000", "http://127.0.0.1", "http://[::1]:8080"}) {
			Check(Modern("server/discover", "", {{"Origin", origin}}).status == 200, "Allow loopback origin");
		}
		for (auto accept : {"", "application/json", "*/*", "application/json, text/event-stream;q=0"}) {
			Check(Modern("server/discover", "", {{"Accept", accept}}).status == 406, "Reject invalid Accept");
		}
		Check(Modern("server/discover", "", {{"Content-Type", "text/plain"}}).status == 415, "Reject content type");
		Check(Modern("server/discover", "", {{"Content-Type", "application/json; charset=utf-8"}}).status == 200,
		      "Accept JSON charset");
		for (auto method : {"GET", "DELETE"}) {
			auto reply = Request("", {}, method);
			Check(reply.status == 405 && reply.headers.find("Allow: POST") != string::npos, "HTTP method unsupported");
		}
		Error(Modern("not/a/method"), 404, -32601);
		auto invalid_tool_input = Modern("tools/call", "\"name\":\"query\",\"arguments\":{}",
		                                {{"Mcp-Name", "query"}});
		Check(invalid_tool_input.status == 200 && invalid_tool_input.body.find("\"isError\":true") != string::npos,
		      "Tool input errors remain MCP tool results: " + invalid_tool_input.body);
		auto sql_error = Modern("tools/call", "\"name\":\"query\",\"arguments\":{\"sql\":\"SELECT nonexistent_column\"}",
		                        {{"Mcp-Name", "query"}});
		Check(sql_error.status == 200 && sql_error.body.find("\"isError\":true") != string::npos,
		      "SQL errors remain tool results: " + sql_error.body);
		Check(Request(string(5000, ' ')).status == 413, "Request byte limit");
		auto capped = Modern("tools/call", "\"name\":\"query\",\"arguments\":{\"sql\":\"SELECT repeat('x',20000) AS value\"}",
		                     {{"Mcp-Name", "query"}});
		Error(capped, 500, -32000);
		Check(capped.body.size() < 8192 && capped.body.find("do not replay writes") != string::npos,
		      "Response cap explicitly describes uncertain execution");
		{
			Socket socket;
			socket.Connect();
			SendAll(socket.fd, "POST /mcp HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\n{");
			char buffer[4096];
			auto received = recv(socket.fd, buffer, sizeof(buffer), 0);
			Check(received >= 0, "HTTP read timeout closes incomplete request within receive deadline");
		}
		Check(Modern().status == 200, "Service healthy after HTTP timeout");
		service.Shutdown();
		if (!std::getenv("QUACK_EXTENSION")) {
			throw std::runtime_error("Set QUACK_EXTENSION for scoped-secret coverage");
		}
		const string quack_call = "\"name\":\"quack_query\",\"arguments\":{\"sql\":\"SELECT 42 AS answer\"}";
		Service missing_secret(true);
		missing_secret.Ready();
		auto missing = Modern("tools/call", quack_call, {{"Mcp-Name", "quack_query"}});
		Check(missing.status == 200 && missing.body.find("\"isError\":true") != string::npos,
		      "Missing scoped credential fails closed: " + missing.body);
		missing_secret.Shutdown();
		Service scoped_secret(true, true);
		scoped_secret.Ready();
		auto scoped = Modern("tools/call", quack_call, {{"Mcp-Name", "quack_query"}});
		Check(scoped.status == 200 && scoped.body.find("\\\"answer\\\":42") != string::npos,
		      "Scoped quack secret authorizes native query: " + scoped.body);
		scoped_secret.Shutdown();
		std::cout << "PASS: " << assertions << " HTTP transport assertions" << std::endl;
		return 0;
	} catch (const std::exception &error) {
		std::cerr << "FAIL after " << assertions << " assertions: " << error.what() << std::endl;
		return 1;
	}
}
