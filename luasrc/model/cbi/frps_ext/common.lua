-- Copyright 2020 lwz322 <lwz322@qq.com>
-- Licensed to the public under the MIT License.

local uci = require "luci.model.uci".cursor()
local util = require "luci.util"
local fs = require "nixio.fs"
local sys = require "luci.sys"

local m, s, o

local function frps_version()
	local file = uci:get("frps_ext", "main", "client_file")

	if not file or file == "" or not fs.stat(file) then
		return "<em style=\"color: red;\">%s</em>" % translate("Invalid client file")
	end

	if not fs.access(file, "rwx", "rx", "rx") then
		fs.chmod(file, 755)
	end

	local version = util.trim(sys.exec("%s -v 2>/dev/null" % file))
	if version == "" then
		return "<em style=\"color: red;\">%s</em>" % translate("Can't get client version")
	end
	return translatef("Version: %s", version)
end

m = Map("frps_ext", "%s - %s" % { translate("Frps (ext)"), translate("Common Settings") },
"<p>%s</p><p>%s</p>" % {
	translate("Frp is a fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet."),
	translatef("For more information, please visit: %s",
		"<a href=\"https://github.com/fatedier/frp\" target=\"_blank\">https://github.com/fatedier/frp</a>")
})

m:append(Template("frps_ext/status_header"))

s = m:section(NamedSection, "main", "frps_ext")
s.addremove = false
s.anonymous = true

s:tab("general", translate("General Options"))
s:tab("log", translate("Log Options"))

o = s:taboption("general", Flag, "enabled", translate("Enabled"))

o = s:taboption("general", Value, "client_file", translate("Client file"), frps_version())
o.datatype = "file"
o.rmempty = false

o = s:taboption("general", ListValue, "run_user", translate("Run daemon as user"))
o:value("", translate("-- default --"))
local user
for user in util.execi("cat /etc/passwd | cut -d':' -f1") do
	o:value(user)
end

o = s:taboption("log", Flag, "enable_logging", translate("Enable logging"))

o = s:taboption("log", Value, "log_file", translate("Log file"))
o:depends("enable_logging", "1")
o.placeholder = "/var/log/frps_ext.log"

o = s:taboption("log", ListValue, "log_level", translate("Log level"))
o:depends("enable_logging", "1")
o:value("trace", translate("Trace"))
o:value("debug", translate("Debug"))
o:value("info", translate("Info"))
o:value("warn", translate("Warn"))
o:value("error", translate("Error"))
o.default = "info"

o = s:taboption("log", Value, "log_max_days", translate("Log max days"))
o:depends("enable_logging", "1")
o.datatype = "uinteger"
o.placeholder = "3"

o = s:taboption("log", Flag, "disable_log_color", translate("Disable log color"))
o:depends("enable_logging", "1")
o.enabled = "true"
o.disabled = "false"

return m
