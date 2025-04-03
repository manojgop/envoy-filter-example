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
    return wrk.format("GET", target_url)
end

