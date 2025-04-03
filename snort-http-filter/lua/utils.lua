local utils = {}

local socket = require("socket")
local ssl = require("ssl")

local proxy_url = os.getenv("PROXY_URL") or "http://127.0.0.1:80"
local protocol, proxy_host, proxy_port = proxy_url:match("^(https?)://([^:/]+):?(%d*)$")
-- Set default port if not provided
if proxy_port == "" then
    if protocol == "http" then
        proxy_port = "80"
    elseif protocol == "https" then
        proxy_port = "443"
    end
end

local function ssl_proxy_connect()
    -- print("Called wrk.connect()")
    local sock = socket.tcp()
    sock:settimeout(5) -- Set timeout for connection

    if proxy_host == nil or proxy_port == nil then
        print("SSL Proxy url: " .. (proxy_url or "nil"))
        error("SSL proxy url expected format is https://ip:port")
    end

    local success, err = sock:connect(proxy_host, proxy_port)
    if not success then
        error("Failed to connect to proxy: " .. err)
    end

    local params = {
        mode = "client",
        protocol = "tlsv1_2",
        verify = "none"
    }
    local ssl_sock, err = ssl.wrap(sock, params)
    if not ssl_sock then
        error("Failed to wrap SSL socket: " .. err)
    end

    local ok, err = ssl_sock:dohandshake()
    if not ok then
        error("SSL handshake failed: " .. err)
    end

    return ssl_sock
end

local function http_proxy_connect()
    -- print("Called wrk.connect()")
    local sock = socket.tcp()
    sock:settimeout(5) -- Set timeout for connection

    local success, err = sock:connect(proxy_host, proxy_port)
    if not success then
        error("Failed to connect to proxy: " .. err)
    end

    return sock
end

function utils.connect()
    if protocol == "https" then
        return ssl_proxy_connect()
    else
        return http_proxy_connect()
    end
end

return utils
