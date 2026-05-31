local cjson = require "cjson.safe"
local http = require "resty.http"
local bit = require "bit"
local parser = require "mqtt_parser"

local function send_connack_error(client_sock, protocol_level)
    local ok, sock_err = pcall(function()
        if protocol_level == 5 then
            local connack = string.char(0x20, 0x03, 0x00, 0x87, 0x00)
            client_sock:send(connack)
        else
            client_sock:send(string.char(0x20, 0x02, 0x00, 0x05))
        end
    end)
    if not ok then
        ngx.log(ngx.WARN, "mqtt auth error sending CONNACK: ", sock_err)
    end
    pcall(function() client_sock:close() end)
end

local function read_packet(sock)
    local timeout = tonumber(os.getenv("MQTT_AUTH_TIMEOUT_MS") or "3000")
    sock:settimeout(timeout)

    local first_byte, err = sock:receive(1)
    if not first_byte then
        return nil, err
    end

    local remaining_length_bytes = {}
    for _ = 1, 4 do
        local byte
        byte, err = sock:receive(1)
        if not byte then
            return nil, err
        end
        remaining_length_bytes[#remaining_length_bytes + 1] = byte
        if bit.band(byte:byte(1), 0x80) == 0 then
            break
        end
    end

    local remaining_length_raw = table.concat(remaining_length_bytes)
    local remaining_length, _, decode_err = parser.decode_remaining_length(remaining_length_raw, 1)
    if not remaining_length then
        return nil, decode_err or "failed to parse mqtt remaining length"
    end

    local payload = ""
    if remaining_length > 0 then
        payload, err = sock:receive(remaining_length)
        if not payload then
            return nil, err
        end
    end

    return first_byte .. remaining_length_raw .. payload
end

local function validate_token(token)
    local validate_url = os.getenv("DOMAIN_TOKEN_VALIDATE_URL")
        or "http://domain:8080/consumers/token/validate"
    local client = http.new()
    client:set_timeout(tonumber(os.getenv("MQTT_AUTH_TIMEOUT_MS") or "3000"))

    local response, err = client:request_uri(validate_url, {
        method = "POST",
        body = cjson.encode({ token = token }),
        headers = {
            ["Content-Type"] = "application/json",
            ["Accept"] = "application/json",
        },
        keepalive = false,
    })

    if not response then
        ngx.log(ngx.WARN, "mqtt token validation request failed: ", err)
        return nil
    end
    if response.status < 200 or response.status >= 300 then
        ngx.log(ngx.WARN, "mqtt token validation returned status ", response.status)
        return nil
    end

    local body = cjson.decode(response.body or "")
    if not body then
        ngx.log(ngx.WARN, "mqtt token validation returned invalid json")
        return nil
    end

    if body.valid ~= true or type(body.consumerId) ~= "string" or body.consumerId == "" then
        return nil
    end

    return body.consumerId
end

local function relay_loop(client, upstream)
    local function relay(from, to, label)
        while true do
            local data, err = from:receiveany(4096)
            if not data then
                if err and err ~= "closed" then
                    ngx.log(ngx.WARN, "mqtt proxy ", label, " read: ", err)
                end
                break
            end
            local ok, send_err = to:send(data)
            if not ok then
                ngx.log(ngx.WARN, "mqtt proxy ", label, " write: ", send_err)
                break
            end
        end
        pcall(function() to:close() end)
        pcall(function() from:close() end)
    end

    client:settimeout(3600000)
    upstream:settimeout(3600000)

    local t1 = ngx.thread.spawn(relay, client, upstream, "c->u")
    local t2 = ngx.thread.spawn(relay, upstream, client, "u->c")
    local ok, err = pcall(ngx.thread.wait, t1, t2)
    if not ok then
        ngx.log(ngx.INFO, "mqtt proxy relay done: ", err)
    end
end

local client_sock, err = ngx.req.socket()
if not client_sock then
    ngx.log(ngx.WARN, "mqtt auth cannot get client socket: ", err)
    return ngx.exit(ngx.ERROR)
end

local packet, err = read_packet(client_sock)
if not packet then
    ngx.log(ngx.WARN, "mqtt auth cannot read CONNECT packet: ", err)
    return ngx.exit(ngx.ERROR)
end

local connect, err = parser.parse_connect(packet)
if not connect then
    ngx.log(ngx.WARN, "mqtt auth cannot parse CONNECT packet: ", err)
    send_connack_error(client_sock, 5)
    return ngx.exit(ngx.ERROR)
end

if connect.protocol_level ~= 5 then
    ngx.log(ngx.WARN, "mqtt auth requires MQTT 5.0, got ", connect.protocol_level)
    send_connack_error(client_sock, connect.protocol_level)
    return ngx.exit(ngx.ERROR)
end

local token = connect.password
if not token or token == "" then
    token = connect.username
end

if not token or token == "" then
    ngx.log(ngx.WARN, "mqtt auth missing token")
    send_connack_error(client_sock, 5)
    return ngx.exit(ngx.ERROR)
end

local consumer_id = validate_token(token)
if not consumer_id then
    ngx.log(ngx.WARN, "mqtt auth rejected consumer (token invalid)")
    send_connack_error(client_sock, 5)
    return ngx.exit(ngx.ERROR)
end

ngx.log(ngx.INFO, "mqtt auth accepted consumer ", consumer_id)

local new_connect = {
    protocol_name = connect.protocol_name,
    protocol_level = connect.protocol_level,
    connect_flags = bit.bor(connect.connect_flags, 0x80),
    keep_alive = connect.keep_alive,
    connect_properties = connect.connect_properties,
    client_id = connect.client_id,
    username = consumer_id,
    password = connect.password,
    will_topic = connect.will_topic,
    will_payload = connect.will_payload,
    will_properties = connect.will_properties,
}

local modified_connect = parser.encode_connect(new_connect)

local upstream_host = os.getenv("MQTT_UPSTREAM_HOST") or "mosquitto"
local upstream_port = tonumber(os.getenv("MQTT_UPSTREAM_PORT") or "1883")

local upstream = ngx.socket.tcp()
upstream:settimeout(tonumber(os.getenv("MQTT_AUTH_TIMEOUT_MS") or "3000"))
local ok, err = upstream:connect(upstream_host, upstream_port)
if not ok then
    ngx.log(ngx.WARN, "mqtt auth cannot connect to upstream ", upstream_host, ":", upstream_port, ": ", err)
    send_connack_error(client_sock, 5)
    return ngx.exit(ngx.ERROR)
end

local ok, err = upstream:send(modified_connect)
if not ok then
    ngx.log(ngx.WARN, "mqtt auth cannot send CONNECT to upstream: ", err)
    send_connack_error(client_sock, 5)
    pcall(function() upstream:close() end)
    return ngx.exit(ngx.ERROR)
end

local connack_data, err = read_packet(upstream)
if not connack_data then
    ngx.log(ngx.WARN, "mqtt auth cannot read CONNACK from upstream: ", err)
    send_connack_error(client_sock, 5)
    pcall(function() upstream:close() end)
    return ngx.exit(ngx.ERROR)
end

local connack, err = parser.parse_connack(connack_data)
if not connack then
    ngx.log(ngx.WARN, "mqtt auth cannot parse CONNACK from upstream: ", err)
    send_connack_error(client_sock, 5)
    pcall(function() upstream:close() end)
    return ngx.exit(ngx.ERROR)
end

local modified_connack = connack_data
if connack.reason_code == 0 then
    modified_connack, err = parser.add_user_property(connack_data, "consumer_id", consumer_id)
    if not modified_connack then
        ngx.log(ngx.WARN, "mqtt auth cannot modify CONNACK (fallback to raw): ", err)
        modified_connack = connack_data
    end
end

local ok, err = client_sock:send(modified_connack)
if not ok then
    ngx.log(ngx.WARN, "mqtt auth cannot send CONNACK to client: ", err)
    pcall(function() upstream:close() end)
    return ngx.exit(ngx.ERROR)
end

relay_loop(client_sock, upstream)
