local utils = require("utils")

init = function(args)
    -- print("Inside init function")
    if #args < 1 then
        error("Usage: wrk -s script.lua <proxy_url> -- <target_url>")
    end

    target_url = args[1]
end

function wrk.connect()
    return utils.connect()
end

request = function()
    local headers = {
        ["Content-Type"] = "application/json"
    }
    local body = '{"key1":"value1", "key2":"value2"}'
    return wrk.format("POST", target_url, headers, body)
end

