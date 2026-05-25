package.path = "/gateway/lua/?.lua;" .. (os.getenv("PWD") or ".") .. "/gateway/lua/?.lua;" .. package.path

local parser = require "mqtt_parser"

local function encode_string(value)
    return string.char(math.floor(#value / 256), #value % 256) .. value
end

local function encode_remaining_length(value)
    local bytes = {}
    repeat
        local encoded = value % 128
        value = math.floor(value / 128)
        if value > 0 then
            encoded = encoded + 128
        end
        bytes[#bytes + 1] = string.char(encoded)
    until value == 0
    return table.concat(bytes)
end

local function connect_packet(client_id, username, password)
    local variable_header = encode_string("MQTT") .. string.char(4, 0xC2, 0, 60)
    local payload = encode_string(client_id) .. encode_string(username) .. encode_string(password)
    local remaining = variable_header .. payload
    return string.char(0x10) .. encode_remaining_length(#remaining) .. remaining
end

local function assert_equal(actual, expected, message)
    if actual ~= expected then
        error((message or "assertion failed") .. ": expected " .. tostring(expected) .. ", got " .. tostring(actual), 2)
    end
end

local parsed = assert(parser.parse_connect(connect_packet(
    "device-client",
    "11111111-1111-1111-1111-111111111111",
    "consumer-token"
)))

assert_equal(parsed.client_id, "device-client", "client id")
assert_equal(parsed.username, "11111111-1111-1111-1111-111111111111", "username")
assert_equal(parsed.password, "consumer-token", "password")

local malformed, err = parser.parse_connect(string.char(0x30, 0x00))
assert_equal(malformed, nil, "malformed packet")
if not err then
    error("expected malformed packet error")
end

print("mqtt_parser tests passed")
