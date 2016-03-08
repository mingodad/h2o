local str_format = string.format

--request methods
--req:authority()
--req:host()
--req:method()
--req:path()
--req:path_normalized()
--req:scheme()
--req:default_port()
--req:remote_user()
--req:upgrade()
--req:version()
--req:bytes_sent()
--req:num_reprocessed()
--req:num_delegated()
--req:http1_is_persistent()
--req:res_is_delegated()
--req:preferred_chunk_size()
--req:header()
--req:send()
--req:send_redirect()
--req:console()
--req:reprocess_request()
--req:start_response()
--req:response_status()
--req:response_reason()
--req:response_content_length()
--req:server_address()
--req:server_port()
--req:remote_address()
--req:remote_port()

function myLua2RequestHandlerHelloProceed(req, data)
	--req:console("======myLua2RequestHandlerHelloProceed")
	local name = data.path
	req:send("Hello " .. name, "text/plain; charset=utf-8")
	return 0
end

function myLua2RequestHandlerHelloStop(req, data)
	req:console("======myLua2RequestHandlerStop")
end

--per request call
function h2oHandleRequest(req)
	local host = req:host() --also req:authority()
	local path = req:path()
	local body = str_format("%s %s %s\n%s:%d %s:%d\n%s", 
		req:method(), req:path(), req:query_string(),
		req:server_address(), req:server_port(), req:remote_address(), req:remote_port(),
		req:scheme())
	--local name = path --path:sub(after_lua_prefix_len)
	req:send(body, "text/plain; charset=utf-8")
	--req:console("======h2oHandleRequest")
	--req:response_status(200)
	--req:response_reason("OK")
	--req:start_response(myLua2RequestHandlerHelloProceed, myLua2RequestHandlerHelloStop, {hosr=host, path=path})
	return 0
end

