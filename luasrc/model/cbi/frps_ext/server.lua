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

o = s:taboption("listen", Value, "bind_port", translate("Bind port"))
o.datatype = "port"
o.rmempty = false

o = s:taboption("listen", Value, "kcp_bind_port", translate("KCP bind port"),
	translate("Optional: UDP port used for KCP protocol, empty means disabled"))
o.datatype = "port"

o = s:taboption("listen", Value, "quic_bind_port", translate("QUIC bind port"),
	translate("Optional: UDP port used for QUIC protocol, empty means disabled"))
o.datatype = "port"

o = s:taboption("listen", Value, "proxy_bind_addr", translate("Proxy bind address"),
	translate("Optional: address that proxy listeners bind to"))
o.datatype = "host"

-- Vhost

o = s:taboption("vhost", Value, "vhost_http_port", translate("Vhost HTTP port"))
o.datatype = "port"

o = s:taboption("vhost", Value, "vhost_https_port", translate("Vhost HTTPS port"))
o.datatype = "port"

o = s:taboption("vhost", Value, "vhost_http_timeout", translate("Vhost HTTP timeout (s)"))
o.datatype = "uinteger"
o.placeholder = "60"

o = s:taboption("vhost", Value, "tcpmux_httpconnect_port", translate("TCPMux HTTP CONNECT port"),
	translate("Optional: enable tcpmux HTTP CONNECT by setting a port"))
o.datatype = "port"

o = s:taboption("vhost", Flag, "tcpmux_passthrough", translate("TCPMux passthrough"),
	translate("If enabled, frps won't modify the TCPMux traffic"))

o = s:taboption("vhost", Value, "subdomain_host", translate("Subdomain host"))

o = s:taboption("vhost", Value, "custom_404_page", translate("Custom 404 page"))
o.datatype = "file"

-- Auth

o = s:taboption("auth", ListValue, "auth_method", translate("Auth method"))
o:value("token", "Token")
o:value("oidc", "OIDC")
o.default = "token"

o = s:taboption("auth", Value, "auth_token", translate("Auth token"))
o.password = true

o = s:taboption("auth", Value, "auth_token_source_file", translate("Token source file"),
	translate("Optional: load token from file; mutually exclusive with auth.token"))
o.datatype = "file"

o = s:taboption("auth", DynamicList, "auth_additional_scopes", translate("Additional scopes"),
	translate("Optional values: HeartBeats, NewWorkConns"))
o.placeholder = "HeartBeats"

o = s:taboption("auth", Value, "auth_oidc_issuer", translate("OIDC issuer"))
o:depends("auth_method", "oidc")

o = s:taboption("auth", Value, "auth_oidc_audience", translate("OIDC audience"))
o:depends("auth_method", "oidc")

o = s:taboption("auth", Flag, "auth_oidc_skip_expiry_check", translate("OIDC skip expiry check"))
o:depends("auth_method", "oidc")

o = s:taboption("auth", Flag, "auth_oidc_skip_issuer_check", translate("OIDC skip issuer check"))
o:depends("auth_method", "oidc")

-- Transport

o = s:taboption("transport", Value, "transport_max_pool_count", translate("Max pool count"),
	translate("Pool size upper bound per proxy"))
o.datatype = "uinteger"
o.placeholder = "5"

o = s:taboption("transport", Flag, "tcp_mux", translate("TCP mux"),
	translate("Enable TCP stream multiplexing between frpc and frps"))
o.enabled = "true"
o.disabled = "false"
o.default = o.enabled

o = s:taboption("transport", Value, "tcp_mux_keepalive_interval", translate("TCP mux keepalive interval (s)"))
o.datatype = "integer"
o.placeholder = "30"

o = s:taboption("transport", Value, "tcp_keepalive", translate("TCP keepalive (s)"),
	translate("Negative disables TCP keepalive probes"))
o.datatype = "integer"
o.placeholder = "7200"

o = s:taboption("transport", Flag, "tcp_fast_open", translate("TCP fast open"))

o = s:taboption("transport", Value, "tcp_fast_open_queue", translate("TCP fast open queue"))
o.datatype = "integer"
o.placeholder = "1024"

o = s:taboption("transport", Value, "heartbeat_timeout", translate("Heartbeat timeout (s)"),
	translate("Negative disables application heartbeat; default depends on TCPMux"))
o.datatype = "integer"

o = s:taboption("transport", Value, "quic_keepalive_period", translate("QUIC keepalive period (s)"))
o.datatype = "integer"
o.placeholder = "10"

o = s:taboption("transport", Value, "quic_max_idle_timeout", translate("QUIC max idle timeout (s)"))
o.datatype = "integer"
o.placeholder = "30"

o = s:taboption("transport", Value, "quic_max_incoming_streams", translate("QUIC max incoming streams"))
o.datatype = "integer"
o.placeholder = "100000"

o = s:taboption("transport", Flag, "tls_force", translate("TLS force"),
	translate("Only accept TLS-encrypted connections"))

o = s:taboption("transport", Value, "tls_cert_file", translate("TLS cert file"))
o.datatype = "file"

o = s:taboption("transport", Value, "tls_key_file", translate("TLS key file"))
o.datatype = "file"

o = s:taboption("transport", Value, "tls_trusted_ca_file", translate("TLS trusted CA file"))
o.datatype = "file"

-- Web / dashboard

o = s:taboption("web", Value, "web_addr", translate("Web addr"))
o.datatype = "host"
o.placeholder = "127.0.0.1"

o = s:taboption("web", Value, "web_port", translate("Web port"),
	translate("Dashboard is enabled only if this is set"))
o.datatype = "port"

o = s:taboption("web", Value, "web_user", translate("Web user"))

o = s:taboption("web", Value, "web_password", translate("Web password"))
o.password = true

o = s:taboption("web", Value, "web_assets_dir", translate("Web assets dir"))

o = s:taboption("web", Flag, "web_pprof_enable", translate("Enable pprof"))

o = s:taboption("web", Value, "web_tls_cert_file", translate("Web TLS cert file"))
o.datatype = "file"

o = s:taboption("web", Value, "web_tls_key_file", translate("Web TLS key file"))
o.datatype = "file"

o = s:taboption("web", Flag, "enable_prometheus", translate("Enable Prometheus"),
	translate("Expose /metrics on web server"))

-- Limits

o = s:taboption("limits", Flag, "detailed_errors_to_client", translate("Detailed errors to client"))

o = s:taboption("limits", Value, "max_ports_per_client", translate("Max ports per client"))
o.datatype = "uinteger"
o.placeholder = "0"

o = s:taboption("limits", Value, "user_conn_timeout", translate("User connection timeout (s)"))
o.datatype = "integer"
o.placeholder = "10"

o = s:taboption("limits", Value, "udp_packet_size", translate("UDP packet size"))
o.datatype = "uinteger"
o.placeholder = "1500"

o = s:taboption("limits", Value, "nathole_analysis_data_reserve_hours", translate("NAT hole analysis reserve hours"))
o.datatype = "uinteger"
o.placeholder = "168"

o = s:taboption("limits", DynamicList, "allow_ports", translate("Allow ports"),
	translate("Each item: single port (e.g. 3001) or range (e.g. 2000-3000)"))
o.placeholder = "2000-3000"

-- Advanced

o = s:taboption("advanced", Value, "ssh_gateway_bind_port", translate("SSH tunnel gateway port"))
o.datatype = "port"

o = s:taboption("advanced", Value, "ssh_gateway_private_key_file", translate("SSH gateway private key file"))
o.datatype = "file"

o = s:taboption("advanced", Value, "ssh_gateway_auto_gen_private_key_path", translate("SSH gateway auto-gen key path"))

o = s:taboption("advanced", Value, "ssh_gateway_authorized_keys_file", translate("SSH gateway authorized keys file"))
o.datatype = "file"

o = s:taboption("advanced", DynamicList, "extra_setting", translate("Extra TOML lines"),
	translate("Raw TOML assignment lines appended to generated config"))
o.placeholder = "transport.bandwidthLimit = \"10MB\""

-- HTTP plugins section
local p
p = m:section(TypedSection, "http_plugin", translate("HTTP Plugins"))
p.anonymous = true
p.addremove = true

p:option(Flag, "enabled", translate("Enabled"))

o = p:option(Value, "name", translate("Name"))
o.rmempty = false

o = p:option(Value, "addr", translate("Addr"), translate("Format: ip:port"))
o.rmempty = false

o = p:option(Value, "path", translate("Path"))
o.rmempty = false

o = p:option(DynamicList, "ops", translate("Ops"),
	translate("Example: Login, NewProxy"))
o.rmempty = false

o = p:option(Flag, "tls_verify", translate("TLS verify"))

return m
