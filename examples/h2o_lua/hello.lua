local str_format = string.format

--per request call
function h2oManageRequest(req)
	local host = req:host() --also req:authority()
	local path = req:path()
	local name = path --path:sub(after_lua_prefix_len)
	req:send("Hello " .. name, "text/plain; charset=utf-8")
	return 0
end

