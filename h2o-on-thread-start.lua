print("Lua thread starting ...")

local h2olib = require("h2olib")

local ffi = require("ffi")
ffi.cdef[[
int myprintf ( const char * format, ... );
]]

ffi.C.myprintf("Hello %s!\n", "world")

local str_format = string.format

local lua_prefix = "/LUA/"
local after_lua_prefix_len = #lua_prefix + 1

local lua2_prefix = "/LUA2/"
local after_lua2_prefix_len = #lua2_prefix + 1

--per thread initialization
function h2oOnThreadStart(ctx)
	if(h2olib.mutex_trylock() == 0) then
		print("Registering lua handler")
		local added = ctx:register_handler_global(lua_prefix)
		added = ctx:register_handler_global(lua2_prefix) or added
		--added = ctx:register_handler_on_host(lua_prefix, "www.example.com")
		if added then
			ctx:sort_handler_global()
		end

		h2olib.usleep(1000); --sleep a bit to allow other threads to be created and skip this code block
		h2olib.mutex_unlock()
	end
end

--per thread finalization
function h2oOnThreadEnd(ctx)
end

--per request call
function h2oManageRequest(req)
	local host = req:host() --also req:authority()
	local path = req:path()
	--ffi.C.myprintf("The path: %s\n", path)
	if path:find(lua_prefix, 1, true) then
		if path:find("hello/", after_lua_prefix_len, true) then
			return myLuaRequestHandlerHello(req, host, path)
		end
		return myLuaRequestHandler(req, host, path)
	elseif path:find(lua2_prefix, 1, true) then
		if path:find("hello2/", after_lua2_prefix_len, true) then
			return myLua2RequestHandlerHello(req, host, path)
		end
		return myLua2RequestHandler(req, host, path)
	end
	return 1
end

local page_template = [==[
<html>
<body>
<h2>%s</h2>
<form method="POST">
<input type=text name=name value="%s">
<input type=submit value=Send>
</form>
</body>
</html>
]==]

function myLuaRequestHandlerHello(req, host, path)
	local name = path:sub(after_lua_prefix_len)
	req:send("Hello " .. name, "text/html")
	return 0
end

function myLua2RequestHandlerHelloProceed(req, data)
	local name = data.path:sub(after_lua2_prefix_len)
	req:send("Hello " .. name, "text/html")
	return 0
end

function myLua2RequestHandlerHelloStop(req, data)
end

function myLua2RequestHandlerHello(req, host, path)
	req:start_response(myLua2RequestHandlerHelloProceed, myLua2RequestHandlerHelloStop, {hosr=host, path=path})
	return 0
end

local function sendForm(req, name, form_name)
	local greeting = str_format("Hello %s", name)
	local page =str_format(page_template, greeting, form_name)
	--[[
	req:response_status(200)
	req:response_reason("OK")
	req:response_content_length(#page)
	req:header("Content-Type", "text/html")
	]]
	--req:header("Author", "DAD")
	--req:send(page, 1)
	req:send(page, "text/html")
end

local lua_path_re = lua_prefix .. "(.+)"

function myLuaRequestHandler(req, host, path)
	
	local method = req:method()
	local name = path:match(lua_path_re)
	if method == "GET" then
		sendForm(req, name .. " GET", "")
	elseif method == "POST" then
		sendForm(req, name .. " POST", req:entity())	
	end
	
	--[[
	print("--Header Accept", req:header("accept"))
	print("--Header Cookie", req:header("cookie"))
	for i=0,1 do
		local tbl = {
			authority = req:authority(),
			method = req:method(),
			path = req:path(), 
			path_normalized = req:path_normalized(),
			scheme = req:scheme(),
			entity = req:entity(),
			upgrade = req:upgrade(),
			version = req:version(),
			bytes_sent = req:bytes_sent(),
			http1_is_persistent = req:http1_is_persistent()
			}
		
		local req_concat = ""
		for k,v in pairs(tbl) do
			req_concat = req_concat .. k .. v
		end
		--print("--- req_concat",  req_concat)
	end
	]]
	--[[
	print("req_concat",  req_concat)
	print("----Rquest authority", req:authority())
	print("----Rquest method", req:method())
	print("----Rquest path", req:path())
	print("----Rquest path_normalized", req:path_normalized())
	print("----Rquest scheme", req:scheme())
	print("----Rquest entity", req:entity())
	print("----Rquest upgrade", req:upgrade())
	print("----Rquest version", req:version())
	print("----Rquest bytes_sent", req:bytes_sent())
	print("----Rquest http1_is_persistent", req:http1_is_persistent())
	]]
	return 0
end

local lua2_path_re = lua2_prefix .. "(.+)"

function myLua2RequestHandlerProceed(req, data)
	
	print("======myLua2RequestHandlerProceed")
	local method = req:method()
	local name = data.path:match(lua2_path_re)
	if method == "GET" then
		sendForm(req, name .. " GET", "")
	elseif method == "POST" then
		sendForm(req, name .. " POST", req:entity())	
	end
	return 0
end

function myLua2RequestHandlerStop(req, data)
	print("======myLua2RequestHandlerStop")
end

function myLua2RequestHandler(req, host, path)
	print("======myLua2RequestHandler")
	req:start_response(myLua2RequestHandlerProceed, myLua2RequestHandlerStop, {hosr=host, path=path})
	print("======myLua2RequestHandler----")
	return 0
end
