-- Copyright 2020 lwz322 <lwz322@qq.com>
-- Licensed to the public under the MIT License.

local m, s, o

m = Map("frps_ext", "%s - %s" % { translate("Frps (ext)"), translate("FRPS Server setting") })

s = m:section(NamedSection, "main", "frps_ext")
s.anonymous = true
s.addremove = false

s:tab("listen", translate("Listen Options"))
s:tab("vhost", translate("Vhost Options"))
s:tab("auth", translate("Auth Options"))
s:tab("transport", translate("Transport Options"))
s:tab("web", translate("Web/Dashboard"))
s:tab("limits", translate("Limits"))
s:tab("advanced", translate("Advanced Options"))

-- Listen

o = s:taboption("listen", Value, "bind_addr", translate("Bind address"))
o.datatype = "host"
o.placeholder = "0.0.0.0"
o.rmempty = false
o.description = translate("Address frps listens on; set to 0.0.0.0 to accept connections on all interfaces.")

o = s:taboption("listen", Value, "bind_port", translate("Bind port"))
o.datatype = "port"
o.rmempty = false
o.description = translate("Main TCP port used for control/work connections from frpc.")

o = s:taboption("listen", Value, "kcp_bind_port", translate("KCP bind port"),
	translate("Optional: UDP port used for KCP protocol, empty means disabled"))
o.datatype = "port"
o.description = translate("UDP port for KCP transport; leave empty to disable KCP.")

o = s:taboption("listen", Value, "quic_bind_port", translate("QUIC bind port"),
	translate("Optional: UDP port used for QUIC protocol, empty means disabled"))
o.datatype = "port"
o.description = translate("UDP port for QUIC transport; leave empty to disable QUIC.")

o = s:taboption("listen", Value, "proxy_bind_addr", translate("Proxy bind address"),
	translate("Optional: address that proxy listeners bind to"))
o.datatype = "host"
o.description = translate("Override bind_addr for proxy listeners (TCP/UDP/http/https).")

-- Vhost

o = s:taboption("vhost", Value, "vhost_http_port", translate("Vhost HTTP port"))
o.datatype = "port"
o.description = translate("Port used for HTTP vhost routing (also used by HTTP plugins).")

o = s:taboption("vhost", Value, "vhost_https_port", translate("Vhost HTTPS port"))
o.datatype = "port"
o.description = translate("Port used for HTTPS vhost routing.")

o = s:taboption("vhost", Value, "vhost_http_timeout", translate("Vhost HTTP timeout (s)"))
o.datatype = "uinteger"
o.placeholder = "60"
o.description = translate("Read/write timeout for HTTP/HTTPS requests in seconds.")

o = s:taboption("vhost", Value, "tcpmux_httpconnect_port", translate("TCPMux HTTP CONNECT port"),
	translate("Optional: enable tcpmux HTTP CONNECT by setting a port"))
o.datatype = "port"
o.description = translate("Expose TCPMux over HTTP CONNECT on this port; leave empty to disable.")

o = s:taboption("vhost", Flag, "tcpmux_passthrough", translate("TCPMux passthrough"),
	translate("If enabled, frps won't modify the TCPMux traffic"))
o.description = translate("Forward TCPMux payload without extra processing; disables layer-7 handling.")

o = s:taboption("vhost", Value, "subdomain_host", translate("Subdomain host"))
o.description = translate("Base domain for subdomain routing, e.g. example.com -> *.example.com.")

o = s:taboption("vhost", Value, "custom_404_page", translate("Custom 404 page"))
o.datatype = "file"
o.description = translate("Path to a custom 404 response page for vhost requests.")

-- Auth

o = s:taboption("auth", ListValue, "auth_method", translate("Auth method"))
o:value("token", "Token")
o:value("oidc", "OIDC")
o.default = "token"
o.description = translate("Client authentication method (token or OIDC).")

o = s:taboption("auth", Value, "auth_token", translate("Auth token"))
o.password = true
o.description = translate("Shared token for token-based auth; leave empty if using OIDC.")

o = s:taboption("auth", Value, "auth_token_source_file", translate("Token source file"),
	translate("Optional: load token from file; mutually exclusive with auth.token"))
o.datatype = "file"
o.description = translate("Read token from this file instead of inline token; cannot be used with auth_token.")

o = s:taboption("auth", DynamicList, "auth_additional_scopes", translate("Additional scopes"),
	translate("Optional values: HeartBeats, NewWorkConns"))
o.placeholder = "HeartBeats"
o.description = translate("Extra scopes allowed for clients (e.g. HeartBeats, NewWorkConns).")

o = s:taboption("auth", Value, "auth_oidc_issuer", translate("OIDC issuer"))
o:depends("auth_method", "oidc")
o.description = translate("Issuer URL for OIDC tokens.")

o = s:taboption("auth", Value, "auth_oidc_audience", translate("OIDC audience"))
o:depends("auth_method", "oidc")
o.description = translate("Expected audience claim for OIDC tokens.")

o = s:taboption("auth", Flag, "auth_oidc_skip_expiry_check", translate("OIDC skip expiry check"))
o:depends("auth_method", "oidc")
o.description = translate("Skip validation of token expiration time (not recommended).")

o = s:taboption("auth", Flag, "auth_oidc_skip_issuer_check", translate("OIDC skip issuer check"))
o:depends("auth_method", "oidc")
o.description = translate("Skip validation of token issuer (not recommended).")

-- Transport

o = s:taboption("transport", Value, "transport_max_pool_count", translate("Max pool count"),
	translate("Upper bound for each proxy's work-connection pool_count requested by clients; higher values are capped here."))
o.datatype = "uinteger"
o.placeholder = "5"
o.description = translate("Caps per-proxy pool_count requested by frpc; excess connections are trimmed to this value.")

o = s:taboption("transport", Flag, "tcp_mux", translate("TCP mux"),
	translate("Enable TCP stream multiplexing between frpc and frps"))
o.enabled = "true"
o.disabled = "false"
o.default = o.enabled
o.description = translate("Reuse one TCP connection for multiple streams; reduces connection overhead.")

o = s:taboption("transport", Value, "tcp_mux_keepalive_interval", translate("TCP mux keepalive interval (s)"))
o.datatype = "integer"
o.placeholder = "30"
o.description = translate("Interval in seconds for TCP mux keepalive pings.")

o = s:taboption("transport", Value, "tcp_keepalive", translate("TCP keepalive (s)"),
	translate("Negative disables TCP keepalive probes"))
o.datatype = "integer"
o.placeholder = "7200"
o.description = translate("SO_KEEPALIVE interval; negative disables TCP keepalive.")

o = s:taboption("transport", Flag, "tcp_fast_open", translate("TCP fast open"))
o.description = translate("Enable TCP Fast Open on listening sockets (requires kernel support).")

o = s:taboption("transport", Value, "tcp_fast_open_queue", translate("TCP fast open queue"))
o.datatype = "integer"
o.placeholder = "1024"
o.description = translate("Backlog size for TCP Fast Open SYN queue.")

o = s:taboption("transport", Value, "heartbeat_timeout", translate("Heartbeat timeout (s)"),
	translate("Negative disables application heartbeat; default depends on TCPMux"))
o.datatype = "integer"
o.description = translate("Timeout for frpc heartbeats; negative disables app-layer heartbeat.")

o = s:taboption("transport", Value, "quic_keepalive_period", translate("QUIC keepalive period (s)"))
o.datatype = "integer"
o.placeholder = "10"
o.description = translate("Interval for QUIC keepalive pings in seconds.")

o = s:taboption("transport", Value, "quic_max_idle_timeout", translate("QUIC max idle timeout (s)"))
o.datatype = "integer"
o.placeholder = "30"
o.description = translate("Maximum idle duration before closing QUIC session.")

o = s:taboption("transport", Value, "quic_max_incoming_streams", translate("QUIC max incoming streams"))
o.datatype = "integer"
o.placeholder = "100000"
o.description = translate("Limit of concurrent incoming QUIC streams per session.")

o = s:taboption("transport", Flag, "tls_force", translate("TLS force"),
	translate("Only accept TLS-encrypted connections"))
o.description = translate("Force clients to use TLS for control/work connections.")

o = s:taboption("transport", Value, "tls_cert_file", translate("TLS cert file"))
o.datatype = "file"
o.description = translate("Server certificate file for TLS listener.")

o = s:taboption("transport", Value, "tls_key_file", translate("TLS key file"))
o.datatype = "file"
o.description = translate("Private key matching the TLS certificate.")

o = s:taboption("transport", Value, "tls_trusted_ca_file", translate("TLS trusted CA file"))
o.datatype = "file"
o.description = translate("CA bundle used to verify client certificates.")

-- Web / dashboard

o = s:taboption("web", Value, "web_addr", translate("Web addr"))
o.datatype = "host"
o.placeholder = "127.0.0.1"
o.description = translate("Dashboard bind address.")

o = s:taboption("web", Value, "web_port", translate("Web port"),
	translate("Dashboard is enabled only if this is set"))
o.datatype = "port"
o.description = translate("Dashboard port; leave empty to disable dashboard.")

o = s:taboption("web", Value, "web_user", translate("Web user"))
o.description = translate("Dashboard basic auth username.")

o = s:taboption("web", Value, "web_password", translate("Web password"))
o.password = true
o.description = translate("Dashboard basic auth password.")

o = s:taboption("web", Value, "web_assets_dir", translate("Web assets dir"))
o.description = translate("Custom static assets directory for dashboard; keep empty to use built-in assets.")

o = s:taboption("web", Flag, "web_pprof_enable", translate("Enable pprof"))
o.description = translate("Expose Go pprof endpoints on the dashboard for profiling.")

o = s:taboption("web", Value, "web_tls_cert_file", translate("Web TLS cert file"))
o.datatype = "file"
o.description = translate("Certificate file for dashboard HTTPS.")

o = s:taboption("web", Value, "web_tls_key_file", translate("Web TLS key file"))
o.datatype = "file"
o.description = translate("Private key for dashboard HTTPS.")

o = s:taboption("web", Flag, "enable_prometheus", translate("Enable Prometheus"),
	translate("Expose /metrics on web server"))
o.description = translate("Expose /metrics for Prometheus scraping on the dashboard listener.")

-- Limits

o = s:taboption("limits", Flag, "detailed_errors_to_client", translate("Detailed errors to client"))
o.description = translate("Return detailed error messages to frpc instead of generic codes.")

o = s:taboption("limits", Value, "max_ports_per_client", translate("Max ports per client"))
o.datatype = "uinteger"
o.placeholder = "0"
o.description = translate("Limit how many ports a single client can open; 0 means unlimited.")

o = s:taboption("limits", Value, "user_conn_timeout", translate("User connection timeout (s)"))
o.datatype = "integer"
o.placeholder = "10"
o.description = translate("Timeout for proxy user connections; increase for slow clients.")

o = s:taboption("limits", Value, "udp_packet_size", translate("UDP packet size"))
o.datatype = "uinteger"
o.placeholder = "1500"
o.description = translate("Maximum UDP packet size forwarded by frps.")

o = s:taboption("limits", Value, "nathole_analysis_data_reserve_hours", translate("NAT hole analysis reserve hours"))
o.datatype = "uinteger"
o.placeholder = "168"
o.description = translate("Retention window (hours) for NAT hole punching analysis data.")

o = s:taboption("limits", DynamicList, "allow_ports", translate("Allow ports"),
	translate("Each item: single port (e.g. 3001) or range (e.g. 2000-3000)"))
o.placeholder = "2000-3000"
o.description = translate("Whitelist of allowed listen ports for clients; empty means no restriction.")

-- Advanced

o = s:taboption("advanced", Value, "ssh_gateway_bind_port", translate("SSH tunnel gateway port"))
o.datatype = "port"
o.description = translate("Enable SSH tunnel gateway on this port; leave empty to disable.")

o = s:taboption("advanced", Value, "ssh_gateway_private_key_file", translate("SSH gateway private key file"))
o.datatype = "file"
o.description = translate("Private key used by the SSH gateway.")

o = s:taboption("advanced", Value, "ssh_gateway_auto_gen_private_key_path", translate("SSH gateway auto-gen key path"))
o.description = translate("Where to auto-generate SSH gateway key if none exists.")

o = s:taboption("advanced", Value, "ssh_gateway_authorized_keys_file", translate("SSH gateway authorized keys file"))
o.datatype = "file"
o.description = translate("authorized_keys file used to validate SSH gateway logins.")

o = s:taboption("advanced", DynamicList, "extra_setting", translate("Extra TOML lines"),
	translate("Raw TOML assignment lines appended to generated config"))
o.placeholder = "transport.bandwidthLimit = \"10MB\""
o.description = translate("Append raw TOML lines for advanced use; one entry per line.")

-- HTTP plugins section
local p
p = m:section(TypedSection, "http_plugin", translate("HTTP Plugins"))
p.anonymous = true
p.addremove = true

o = p:option(Flag, "enabled", translate("Enabled"))
o.description = translate("Enable or disable this HTTP plugin entry.")

o = p:option(Value, "name", translate("Name"))
o.rmempty = false
o.description = translate("Plugin name shown in frps logs.")

o = p:option(Value, "addr", translate("Addr"), translate("Format: ip:port"))
o.rmempty = false
o.description = translate("Backend service address (ip:port) for this plugin.")

o = p:option(Value, "path", translate("Path"))
o.rmempty = false
o.description = translate("HTTP path the plugin will be invoked on.")

o = p:option(DynamicList, "ops", translate("Ops"),
	translate("Example: Login, NewProxy"))
o.rmempty = false
o.description = translate("Operations handled by this plugin, e.g. Login or NewProxy.")

o = p:option(Flag, "tls_verify", translate("TLS verify"))
o.description = translate("Verify TLS certificate when calling the plugin backend.")

return m
