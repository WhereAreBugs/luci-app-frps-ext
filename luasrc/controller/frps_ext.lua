-- Copyright 2020 lwz322 <lwz322@qq.com>
-- Licensed to the public under the MIT License.

local http = require "luci.http"
local uci = require "luci.model.uci".cursor()
local sys = require "luci.sys"
local nixio = require "nixio"

module("luci.controller.frps_ext", package.seeall)

function index()
	if not nixio.fs.access("/etc/config/frps_ext") then
		return
	end

	local page = entry({"admin", "services", "frps-ext"},
		firstchild(), _("Frps (ext)"))
	page.dependent = false
	page.i18n = "frps-ext"

	entry({"admin", "services", "frps-ext", "common"},
		cbi("frps_ext/common"), _("Settings"), 1)

	entry({"admin", "services", "frps-ext", "server"},
		cbi("frps_ext/server"), _("Server"), 2).leaf = true

	entry({"admin", "services", "frps-ext", "status"}, call("action_status"))
end

function action_status()
	local running = false

	local client = uci:get("frps_ext", "main", "client_file")
	if client and client ~= "" then
		local file_name = client:match(".*/([^/]+)$") or ""
		if file_name ~= "" then
			running = sys.call("pidof %s >/dev/null" % file_name) == 0
		end
	end

	http.prepare_content("application/json")
	http.write_json({
		running = running
	})
end
