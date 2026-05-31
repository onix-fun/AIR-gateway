local cjson = require "cjson.safe"
local http = require "resty.http"
local parser = require "mqtt_parser"

local function send_connack_error(protocol_level)
    local sock = ngx.req.socket()
    if sock then
        if protocol_level == 5 then
            -- MQTT 5.0: session_present=0, reason=0x87 (Not Authorized), properties_length=0
            sock:send(string.char(0x20, 0x03, 0x00, 0x87, 0x00))
        else
            -- MQTT 3.1.1: reason=5 (Not Authorized)
            sock:send(string.char(0x20, 0x02, 0x00, 0x05))
        end
    end
    return ngx.exit(ngx.ERROR)
end

local function read_connect_packet(sock)
    local timeout = tonumber(os.getenv("MQTT_AUTH_TIMEOUT_MS") or "3000")
    sock:settimeout(timeout)

    local data, err = sock:peek(2)
    if not data then
        return nil, err or "failed to peek mqtt header"
    end

    local total_length
    for size = 2, 5 do
        data, err = sock:peek(size)
        if not data then
            return nil, err or "failed to peek mqtt remaining length"
        end
        total_length = parser.packet_length(data)
        if total_length then
            break
        end
    end

    if not total_length then
        return nil, "failed to parse mqtt packet length"
    end

    data, err = sock:peek(total_length)
    if not data then
        return nil, err or "failed to peek complete mqtt connect"
    end

    return data
end

local function validate_token(consumer_id, token)
    local validate_url = os.getenv("DOMAIN_TOKEN_VALIDATE_URL") or "http://domain:8080/consumers/token/validate"
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
        return false
    end
    if response.status < 200 or response.status >= 300 then
        ngx.log(ngx.WARN, "mqtt token validation returned status ", response.status)
        return false
    end

    local body = cjson.decode(response.body or "")
    if not body then
        ngx.log(ngx.WARN, "mqtt token validation returned invalid json")
        return false
    end

    return body.valid == true and body.consumerId == consumer_id
end

local sock, sock_err = ngx.req.socket()
if not sock then
    ngx.log(ngx.WARN, "mqtt auth cannot get request socket: ", sock_err)
    return send_connack_error()
end

local packet, packet_err = read_connect_packet(sock)
if not packet then
    ngx.log(ngx.WARN, "mqtt auth cannot read CONNECT packet: ", packet_err)
    return send_connack_error()
end

local connect, parse_err = parser.parse_connect(packet)
if not connect then
    ngx.log(ngx.WARN, "mqtt auth cannot parse CONNECT packet: ", parse_err)
    return send_connack_error()
end

if not connect.username or connect.username == "" or not connect.password or connect.password == "" then
    ngx.log(ngx.WARN, "mqtt auth missing username/password")
    return send_connack_error(connect.protocol_level)
end

if not validate_token(connect.username, connect.password) then
    ngx.log(ngx.WARN, "mqtt auth rejected consumer ", connect.username)
    return send_connack_error(connect.protocol_level)
end

ngx.log(ngx.INFO, "mqtt auth accepted consumer ", connect.username)
