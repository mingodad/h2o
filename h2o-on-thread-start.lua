print("Lua thread starting ...")
local str_format = string.format

--per thread initialization
function h2oOnThreadStart(ctx)
	ctx:register_handler_global("/LUA/")
	--ctx:register_handler_on_host("/LUA/", "www.example.com")
end

--per thread finalization
function h2oOnThreadEnd(ctx)
end

--per request call
function h2oManageRequest(req)
	local host = req:host() --also req:authority()
	local path = req:path()
	if path:find("/LUA/", 1, true) then
		return myLuaRequestHandler(req, host, path)
	end
	return 0
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


function myLuaRequestHandler(req, host, path)
	
	local method = req:method()
	local name = path:match("/LUA/(.+)")
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