#include "server/http_server_transport.hpp"

// Include httplib from DuckDB's third_party
// Note: This must be included before other headers that might conflict
#include "httplib.hpp"
#include "json_utils.hpp"

#include <iostream>
#include <sstream>
#include <algorithm>
#include <cctype>

namespace duckdb {

// Constant-time string comparison to prevent timing attacks on auth tokens.
//
// Uses a fixed-size comparison buffer so the iteration count is independent
// of both input lengths.  Earlier versions iterated max(a,b) times which
// still let an attacker probe for the expected token length by sending
// increasingly long inputs and observing the timing transition.
//
// 256 bytes is sufficient for "Bearer " (7 bytes) + any reasonable token.
static bool ConstantTimeEquals(const string &a, const string &b) {
	static constexpr size_t kCompareSize = 256;

	// Strings longer than the buffer cannot be valid tokens;
	// return false without constant-time guarantees since the
	// attacker already knows their own input length.
	if (a.size() > kCompareSize || b.size() > kCompareSize) {
		return false;
	}

	// Copy into fixed-size volatile buffers so the compiler cannot
	// reason about their contents or eliminate the comparison loop.
	// Byte-by-byte copy is required because memcpy cannot target volatile.
	volatile unsigned char buf_a[kCompareSize] = {};
	volatile unsigned char buf_b[kCompareSize] = {};
	for (size_t i = 0; i < a.size(); i++) {
		buf_a[i] = static_cast<unsigned char>(a[i]);
	}
	for (size_t i = 0; i < b.size(); i++) {
		buf_b[i] = static_cast<unsigned char>(b[i]);
	}

	// Length mismatch feeds into the result but does not short-circuit.
	volatile unsigned char result = (a.size() != b.size()) ? 1 : 0;

	// Fixed iteration count -- no timing correlation with either string.
	for (size_t i = 0; i < kCompareSize; i++) {
		result |= buf_a[i] ^ buf_b[i];
	}
	return result == 0;
}

// Helper: determine the CORS origin header value for a given request.
// Returns empty string if CORS is disabled or the origin is not allowed.
static string GetCorsOriginHeader(const HTTPServerConfig &config, const string &request_origin) {
	if (config.cors_origins.empty()) {
		return ""; // CORS disabled
	}
	if (config.cors_origins == "*") {
		return "*"; // Wildcard
	}
	// Check if request origin matches any configured origin
	// Parse comma-separated origin list
	std::istringstream stream(config.cors_origins);
	string origin;
	while (std::getline(stream, origin, ',')) {
		// Trim whitespace
		size_t start = origin.find_first_not_of(" \t");
		size_t end = origin.find_last_not_of(" \t");
		if (start != string::npos && end != string::npos) {
			origin = origin.substr(start, end - start + 1);
		}
		if (origin == request_origin) {
			return request_origin; // Return specific origin (not wildcard)
		}
	}
	return ""; // Origin not allowed
}

static string Trim(const string &value) {
	auto first = value.find_first_not_of(" \t");
	return first == string::npos ? "" : value.substr(first, value.find_last_not_of(" \t") - first + 1);
}

static bool AllowedOrigin(const HTTPServerConfig &config, const string &origin) {
	if (origin.empty()) {
		return true;
	}
	if (!config.cors_origins.empty()) {
		return !GetCorsOriginHeader(config, origin).empty();
	}
	// Match the complete authority, never a hostname suffix or userinfo component.
	for (const auto &scheme : {"http://", "https://"}) {
		for (const auto &host : {"localhost", "127.0.0.1", "[::1]"}) {
			string prefix = string(scheme) + host;
			if (origin == prefix) {
				return true;
			}
			if (origin.compare(0, prefix.size() + 1, prefix + ":") == 0) {
				auto port = origin.substr(prefix.size() + 1);
				if (!port.empty() && port.size() <= 5 &&
				    std::all_of(port.begin(), port.end(), [](char c) { return c >= '0' && c <= '9'; })) {
					auto number = std::stoi(port);
					return number > 0 && number <= 65535;
				}
			}
		}
	}
	return false;
}

static bool Accepts(const string &header, const string &expected) {
	std::istringstream values(header);
	string value;
	while (std::getline(values, value, ',')) {
		std::istringstream parameters(value);
		string media;
		std::getline(parameters, media, ';');
		media = Trim(media);
		std::transform(media.begin(), media.end(), media.begin(), [](unsigned char c) { return std::tolower(c); });
		bool allowed = true;
		string parameter;
		while (std::getline(parameters, parameter, ';')) {
			parameter = Trim(parameter);
			if (parameter.compare(0, 2, "q=") == 0) {
				try {
					allowed = std::stod(parameter.substr(2)) > 0;
				} catch (...) {
					allowed = false;
				}
			}
		}
		if (media == expected && allowed) {
			return true;
		}
	}
	return false;
}

static void RPCError(CPPHTTPLIB_NAMESPACE::Response &res, int status, int code, const string &message,
	                 yyjson_val *id = nullptr, const string &requested_version = "") {
	auto doc = JSONUtils::CreateDocument();
	auto root = JSONUtils::CreateMCPMessage(doc);
	yyjson_mut_doc_set_root(doc, root);
	if (id) {
		yyjson_mut_obj_add_val(doc, root, "id", yyjson_val_mut_copy(doc, id));
	}
	auto error = JSONUtils::CreateObject(doc);
	JSONUtils::AddInt(doc, error, "code", code);
	JSONUtils::AddString(doc, error, "message", message);
	if (!requested_version.empty()) {
		auto data = JSONUtils::CreateObject(doc);
		JSONUtils::AddString(doc, data, "requested", requested_version);
		auto supported = JSONUtils::CreateArray(doc);
		for (auto version : {"2026-07-28", "2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}) {
			JSONUtils::ArrayAddString(doc, supported, version);
		}
		JSONUtils::AddArray(doc, data, "supported", supported);
		JSONUtils::AddObject(doc, error, "data", data);
	}
	JSONUtils::AddObject(doc, root, "error", error);
	res.status = status;
	res.set_content(JSONUtils::Serialize(doc), "application/json");
	JSONUtils::FreeDocument(doc);
}

static bool DecodeHeaderName(const string &value, string &decoded) {
	constexpr const char *prefix = "=?base64?";
	constexpr size_t prefix_length = 9;
	if (value.size() >= prefix_length + 2 && value.compare(0, prefix_length, prefix) == 0 &&
	    value.compare(value.size() - 2, 2, "?=") == 0) {
		auto encoded = value.substr(prefix_length, value.size() - prefix_length - 2);
		static const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
		if (encoded.size() % 4 != 0) {
			return false;
		}
		decoded.clear();
		for (size_t i = 0; i < encoded.size(); i += 4) {
			uint32_t bits = 0;
			size_t padding = 0;
			for (size_t j = 0; j < 4; j++) {
				auto c = encoded[i + j];
				auto index = alphabet.find(c);
				if (c == '=') {
					if (j < 2 || i + 4 != encoded.size()) {
						return false;
					}
					padding++;
					index = 0;
				} else if (index == string::npos || padding) {
					return false;
				}
				bits = (bits << 6) | static_cast<uint32_t>(index);
			}
			if ((padding == 1 && (bits & 0xff)) || (padding == 2 && (bits & 0xffff))) {
				return false;
			}
			decoded.push_back(static_cast<char>(bits >> 16));
			if (padding < 2) decoded.push_back(static_cast<char>(bits >> 8));
			if (padding == 0) decoded.push_back(static_cast<char>(bits));
		}
		return true;
	}
	if (Trim(value) != value || !std::all_of(value.begin(), value.end(), [](unsigned char c) {
		    return (c >= 0x20 && c <= 0x7e) || c == '\t';
	    })) {
		return false;
	}
	decoded = value;
	return true;
}

// Helper to set up common routes on a server (works with both Server and SSLServer)
template <typename ServerType>
void SetupRoutes(ServerType &server, const HTTPServerConfig &config,
                 HTTPServerTransport::RequestHandler &request_handler) {
	server.new_task_queue = [&config] {
		return new CPPHTTPLIB_NAMESPACE::ThreadPool(config.max_connections, config.max_connections);
	};
	server.set_payload_max_length(config.max_request_bytes);
	server.set_read_timeout(config.http_io_timeout_seconds);
	server.set_write_timeout(config.http_io_timeout_seconds);
	server.set_keep_alive_timeout(config.http_io_timeout_seconds);
	server.set_pre_routing_handler([&config](const CPPHTTPLIB_NAMESPACE::Request &req,
	                                      CPPHTTPLIB_NAMESPACE::Response &res) {
		if ((req.has_header("Origin") && req.get_header_value("Origin").empty()) ||
		    req.get_header_value_count("Origin") > 1 || !AllowedOrigin(config, req.get_header_value("Origin"))) {
			RPCError(res, 403, -32003, "Forbidden origin");
			return CPPHTTPLIB_NAMESPACE::Server::HandlerResponse::Handled;
		}
		return CPPHTTPLIB_NAMESPACE::Server::HandlerResponse::Unhandled;
	});
	// Configure CORS preflight if enabled
	if (!config.cors_origins.empty()) {
		server.Options(".*", [&config](const CPPHTTPLIB_NAMESPACE::Request &req, CPPHTTPLIB_NAMESPACE::Response &res) {
			string origin = req.get_header_value("Origin");
			string cors_value = GetCorsOriginHeader(config, origin);
			if (!cors_value.empty()) {
				res.set_header("Access-Control-Allow-Origin", cors_value);
				res.set_header("Access-Control-Allow-Methods", "POST, GET, OPTIONS");
				res.set_header("Access-Control-Allow-Headers", "Content-Type, Authorization");
				res.set_header("Access-Control-Max-Age", "86400");
				if (cors_value != "*") {
					res.set_header("Vary", "Origin");
				}
			}
			res.status = 204;
		});
	}

	// Handler for MCP requests
	auto mcp_handler = [&config, &request_handler](const CPPHTTPLIB_NAMESPACE::Request &req,
	                                               CPPHTTPLIB_NAMESPACE::Response &res) {
		// Check authentication if configured
		if (!config.auth_token.empty()) {
			auto auth_header = req.get_header_value("Authorization");
			if (auth_header.empty()) {
				// No credentials provided
				res.status = 401;
				res.set_header("WWW-Authenticate", "Bearer");
				res.set_content(
				    R"({"jsonrpc":"2.0","error":{"code":-32001,"message":"Unauthorized: authentication required"},"id":null})",
				    "application/json");
				return;
			}
			string expected = "Bearer " + config.auth_token;
			if (!ConstantTimeEquals(auth_header, expected)) {
				// Invalid credentials provided
				res.status = 403;
				res.set_content(
				    R"({"jsonrpc":"2.0","error":{"code":-32003,"message":"Forbidden: invalid credentials"},"id":null})",
				    "application/json");
				return;
			}
		}

		// Set CORS headers on response
		if (!config.cors_origins.empty()) {
			string origin = req.get_header_value("Origin");
			string cors_value = GetCorsOriginHeader(config, origin);
			if (!cors_value.empty()) {
				res.set_header("Access-Control-Allow-Origin", cors_value);
				if (cors_value != "*") {
					res.set_header("Vary", "Origin");
				}
			}
		}

		auto content_type = Trim(req.get_header_value("Content-Type").substr(0, req.get_header_value("Content-Type").find(';')));
		std::transform(content_type.begin(), content_type.end(), content_type.begin(),
		               [](unsigned char c) { return std::tolower(c); });
		if (content_type != "application/json") {
			RPCError(res, 415, -32600, "Content-Type must be application/json");
			return;
		}
		auto doc = yyjson_read(req.body.data(), req.body.size(), 0);
		DocGuard guard {doc};
		if (!doc) {
			RPCError(res, 400, -32700, "Parse error");
			return;
		}
		auto root = yyjson_doc_get_root(doc);
		auto id = yyjson_is_obj(root) ? yyjson_obj_get(root, "id") : nullptr;
		auto params = yyjson_is_obj(root) ? yyjson_obj_get(root, "params") : nullptr;
		if (!yyjson_is_obj(root) || JSONUtils::GetString(root, "jsonrpc") != "2.0" ||
		    !yyjson_is_str(yyjson_obj_get(root, "method")) ||
		    (id && !yyjson_is_str(id) && !yyjson_is_int(id)) || yyjson_obj_get(root, "result") ||
		    yyjson_obj_get(root, "error")) {
			RPCError(res, 400, -32600, "Invalid JSON-RPC request");
			return;
		}
		if (params && !yyjson_is_obj(params)) {
			RPCError(res, 400, -32602, "Params must be an object", id);
			return;
		}
		auto method = JSONUtils::GetString(root, "method");
		auto meta = params ? yyjson_obj_get(params, "_meta") : nullptr;
		auto body_version = JSONUtils::GetString(meta, "io.modelcontextprotocol/protocolVersion");
		auto version = req.get_header_value("MCP-Protocol-Version");
		bool modern = version == "2026-07-28" || !body_version.empty();
		// Keep handshake-era clients working byte-for-byte: the 2026 transport
		// requires both representations, while the legacy endpoint did not.
		if (modern && (!Accepts(req.get_header_value("Accept"), "application/json") ||
		               !Accepts(req.get_header_value("Accept"), "text/event-stream"))) {
			RPCError(res, 406, -32600, "Accept must include application/json and text/event-stream", id);
			return;
		}
		if (req.get_header_value_count("MCP-Protocol-Version") > 1 ||
		    (modern && (version.empty() || version != body_version))) {
			RPCError(res, 400, -32020, "Header mismatch: MCP-Protocol-Version", id);
			return;
		}
		if (!version.empty() && version != "2026-07-28" && version != "2025-11-25" &&
		    version != "2025-06-18" && version != "2025-03-26" && version != "2024-11-05") {
			RPCError(res, 400, -32022, "Unsupported protocol version", id, version);
			return;
		}
		if (modern) {
			if (req.get_header_value_count("Mcp-Method") != 1 || req.get_header_value("Mcp-Method") != method) {
				RPCError(res, 400, -32020, "Header mismatch: Mcp-Method", id);
				return;
			}
			if (method == "tools/call" || method == "prompts/get" || method == "resources/read") {
				auto name = yyjson_obj_get(params, method == "resources/read" ? "uri" : "name");
				string decoded;
				if (!yyjson_is_str(name) || req.get_header_value_count("Mcp-Name") != 1 ||
				    !DecodeHeaderName(req.get_header_value("Mcp-Name"), decoded) ||
				    decoded != string(yyjson_get_str(name), yyjson_get_len(name))) {
					RPCError(res, 400, -32020, "Header mismatch: Mcp-Name", id);
					return;
				}
			}
		}
		// Socket timeouts do not cancel the handler. Never replay a write after a disconnect.
		try {
			string response = request_handler(req.body);
			if (!id && response.empty()) {
				res.status = 202;
				return;
			}
			if (response.size() > config.max_response_bytes) {
				RPCError(res, 500, -32000,
				         "Response exceeds configured byte limit; execution may have completed; do not replay writes", id);
				return;
			}
			auto response_doc = yyjson_read(response.data(), response.size(), 0);
			DocGuard response_guard {response_doc};
			if (!response_doc) {
				RPCError(res, 500, -32603, "Invalid handler response", id);
				return;
			}
			auto error = yyjson_obj_get(yyjson_doc_get_root(response_doc), "error");
			if (error) {
				auto code = JSONUtils::GetInt(error, "code");
				res.status = code == -32601 ? 404 : code == -32603 ? 500 : 400;
			} else if (!id) {
				res.status = 202;
				return;
			}
			res.set_content(response, "application/json");
		} catch (const std::exception &e) {
			// Log full error internally but return a generic message to the client
			// to avoid leaking internal details (stack traces, file paths, etc.)
			(void)e; // Suppress unused variable warning; in production, log e.what() here
			res.status = 500;
			res.set_content(R"({"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal server error"},"id":null})",
			                "application/json");
		}
	};

	// Main MCP endpoint
	server.Post("/", mcp_handler);

	// Alternative MCP endpoint
	server.Post("/mcp", mcp_handler);
	auto method_not_allowed = [](const CPPHTTPLIB_NAMESPACE::Request &, CPPHTTPLIB_NAMESPACE::Response &res) {
		res.status = 405;
		res.set_header("Allow", "POST");
	};
	server.Get("/mcp", method_not_allowed);
	server.Delete("/mcp", method_not_allowed);
	server.Get("/", method_not_allowed);
	server.Delete("/", method_not_allowed);

	// Health check endpoint (conditionally enabled, optionally auth-protected)
	if (config.enable_health_endpoint) {
		server.Get("/health", [&config](const CPPHTTPLIB_NAMESPACE::Request &req, CPPHTTPLIB_NAMESPACE::Response &res) {
			// Check authentication if required for health endpoint
			if (config.auth_health_endpoint && !config.auth_token.empty()) {
				auto auth_header = req.get_header_value("Authorization");
				if (auth_header.empty()) {
					res.status = 401;
					res.set_header("WWW-Authenticate", "Bearer");
					res.set_content(R"({"error":"Unauthorized"})", "application/json");
					return;
				}
				string expected = "Bearer " + config.auth_token;
				if (!ConstantTimeEquals(auth_header, expected)) {
					res.status = 403;
					res.set_content(R"({"error":"Forbidden"})", "application/json");
					return;
				}
			}
			res.set_content(R"({"status":"ok"})", "application/json");
		});
	}
}

HTTPServerTransport::HTTPServerTransport(const HTTPServerConfig &config)
    : config(config), running(false), stop_requested(false), actual_port(0), server_ptr(nullptr) {
}

HTTPServerTransport::~HTTPServerTransport() {
	Stop();
}

bool HTTPServerTransport::Start(RequestHandler handler) {
	if (running.load()) {
		return true; // Already running
	}

	request_handler = std::move(handler);
	stop_requested = false; // Reset stop flag for potential restart
	running = true;

	{
		std::lock_guard<std::mutex> lock(startup_mutex);
		startup_complete = false;
	}

	// Start server in background thread
	server_thread = make_uniq<std::thread>(&HTTPServerTransport::ServerLoop, this);

	// Wait for ServerLoop to signal bind success/failure
	{
		std::unique_lock<std::mutex> lock(startup_mutex);
		startup_cv.wait(lock, [this] { return startup_complete; });
	}

	return running.load();
}

bool HTTPServerTransport::Run(RequestHandler handler) {
	if (running.load()) {
		return false; // Already running
	}

	request_handler = std::move(handler);
	stop_requested = false;
	running = true;

	// Run server in calling thread (blocks until Stop() is called)
	ServerLoop();

	return true;
}

void HTTPServerTransport::Stop() {
	stop_requested = true;
	running = false;

	// Stop the httplib server if it's running
	{
		std::lock_guard<std::mutex> lock(server_mutex);
		if (server_ptr) {
			// Cast and stop the server - this will cause listen_after_bind to return
			static_cast<CPPHTTPLIB_NAMESPACE::Server *>(server_ptr)->stop();
		}
	}

	if (server_thread && server_thread->joinable()) {
		server_thread->join();
	}
	server_thread.reset();
}

bool HTTPServerTransport::IsRunning() const {
	return running.load();
}

int HTTPServerTransport::GetPort() const {
	return actual_port.load();
}

string HTTPServerTransport::GetConnectionInfo() const {
	return "HTTP MCP Server at http://" + config.host + ":" + std::to_string(actual_port.load());
}

void HTTPServerTransport::ServerLoop() {
	// Helper to signal startup complete (success or failure)
	auto signal_startup = [this]() {
		std::lock_guard<std::mutex> lock(startup_mutex);
		startup_complete = true;
		startup_cv.notify_one();
	};

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
	if (config.use_ssl) {
		// HTTPS server with SSL
		if (config.cert_path.empty() || config.key_path.empty()) {
			running = false;
			signal_startup();
			return;
		}

		CPPHTTPLIB_NAMESPACE::SSLServer server(config.cert_path.c_str(), config.key_path.c_str());

		if (!server.is_valid()) {
			running = false;
			signal_startup();
			return;
		}

		SetupRoutes(server, config, request_handler);

		// Bind and listen
		int port = config.port;
		if (!server.bind_to_port(config.host.c_str(), port)) {
			running = false;
			signal_startup();
			return;
		}

		actual_port = port;

		// Store server pointer so Stop() can call stop() on it
		// Note: SSLServer inherits from Server, so the base class pointer works for stop()
		{
			std::lock_guard<std::mutex> lock(server_mutex);
			server_ptr = static_cast<CPPHTTPLIB_NAMESPACE::Server *>(&server);
		}

		// Check if stop was requested before we started listening
		if (stop_requested.load()) {
			std::lock_guard<std::mutex> lock(server_mutex);
			server_ptr = nullptr;
			running = false;
			signal_startup();
			return;
		}

		signal_startup();
		server.listen_after_bind();

		// Clear pointer after server stops
		{
			std::lock_guard<std::mutex> lock(server_mutex);
			server_ptr = nullptr;
		}
		running = false;
		return;
	}
#endif

	// HTTP server (no SSL)
	CPPHTTPLIB_NAMESPACE::Server server;

	SetupRoutes(server, config, request_handler);

	// Bind and listen
	int port = config.port;
	if (!server.bind_to_port(config.host.c_str(), port)) {
		running = false;
		signal_startup();
		return;
	}

	actual_port = port;

	// Store server pointer so Stop() can call stop() on it
	{
		std::lock_guard<std::mutex> lock(server_mutex);
		server_ptr = &server;
	}

	// Check if stop was requested before we started listening
	if (stop_requested.load()) {
		std::lock_guard<std::mutex> lock(server_mutex);
		server_ptr = nullptr;
		running = false;
		signal_startup();
		return;
	}

	// Signal that bind succeeded and server is ready
	signal_startup();

	// Run the server (this blocks until server.stop() is called)
	server.listen_after_bind();

	// Clear pointer after server stops
	{
		std::lock_guard<std::mutex> lock(server_mutex);
		server_ptr = nullptr;
	}
	running = false;
}

} // namespace duckdb
