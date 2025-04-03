local utils = require("utils")
local cjson = require("cjson")

local json_file = os.getenv("JSON_FILE")

local request_body = nil

-- Function to load and parse a JSON file
function load_json_file(file_path)
    local file = io.open(file_path, "r") -- Open the file in read mode
    if not file then
        error("Could not open file: " .. file_path)
    end
    local content = file:read("*all") -- Read the entire file content
    file:close()
    return cjson.decode(content) -- Parse JSON content into a Lua table
end

function init(args)
    -- print("Inside init function")
    if #args < 1 then
        error("Usage: wrk -s script.lua <proxy_url> -- <target_url>")
    end

    target_url = args[1]

    -- Load the JSON data from a file
    local json_data = load_json_file(json_file)

    -- Convert Lua table back to JSON string for POST body
    request_body = cjson.encode(json_data)

end

function wrk.connect()
    return utils.connect()
end

request = function()
    local headers = {
        ["Content-Type"] = "application/json"
    }
    return wrk.format("POST", target_url, headers, request_body)
end

