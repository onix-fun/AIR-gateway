local bit = require "bit"

local M = {}

local MQTT_CONNECT_PACKET_TYPE = 0x10

local function read_u16(data, position)
    if position + 1 > #data then
        return nil, position, "unexpected end of packet"
    end
    return data:byte(position) * 256 + data:byte(position + 1), position + 2
end

local function read_bytes(data, position)
    local length
    length, position = read_u16(data, position)
    if not length then
        return nil, position, "unexpected end of packet"
    end
    local last = position + length - 1
    if last > #data then
        return nil, position, "unexpected end of packet"
    end
    return data:sub(position, last), last + 1
end

function M.decode_remaining_length(data, position)
    local multiplier = 1
    local value = 0

    for index = position, position + 3 do
        local encoded = data:byte(index)
        if not encoded then
            return nil, nil, "remaining length is incomplete"
        end

        value = value + bit.band(encoded, 127) * multiplier
        if bit.band(encoded, 128) == 0 then
            return value, index + 1
        end
        multiplier = multiplier * 128
    end

    return nil, nil, "remaining length is malformed"
end

function M.packet_length(data)
    if #data < 2 then
        return nil, "packet header is incomplete"
    end
    local packet_type = bit.band(data:byte(1), 0xF0)
    if packet_type ~= MQTT_CONNECT_PACKET_TYPE then
        return nil, "first MQTT packet must be CONNECT"
    end

    local remaining_length, payload_position, err = M.decode_remaining_length(data, 2)
    if err then
        return nil, err
    end

    return payload_position + remaining_length - 1
end

function M.parse_connect(data)
    local total_length, packet_err = M.packet_length(data)
    if not total_length then
        return nil, packet_err
    end
    if #data < total_length then
        return nil, "connect packet is incomplete"
    end

    local position = select(2, M.decode_remaining_length(data, 2))

    local protocol_name, protocol_err
    protocol_name, position, protocol_err = read_bytes(data, position)
    if protocol_err then
        return nil, protocol_err
    end
    if protocol_name ~= "MQTT" and protocol_name ~= "MQIsdp" then
        return nil, "unsupported mqtt protocol"
    end

    local protocol_level = data:byte(position)
    local connect_flags = data:byte(position + 1)
    if not protocol_level or not connect_flags then
        return nil, "connect flags are incomplete"
    end
    position = position + 4 -- protocol level, flags, keepalive msb/lsb

    if protocol_level == 5 then
        local _, next_position, properties_err = M.decode_remaining_length(data, position)
        if properties_err then
            return nil, properties_err
        end
        local properties_length = 0
        properties_length, next_position = M.decode_remaining_length(data, position)
        position = next_position + properties_length
    elseif protocol_level ~= 4 and protocol_level ~= 3 then
        return nil, "unsupported mqtt protocol level"
    end

    local client_id
    client_id, position = read_bytes(data, position)
    if not client_id then
        return nil, "client id is incomplete"
    end

    local has_username = bit.band(connect_flags, 0x80) ~= 0
    local has_password = bit.band(connect_flags, 0x40) ~= 0
    local has_will = bit.band(connect_flags, 0x04) ~= 0

    if has_will then
        local will_topic
        will_topic, position = read_bytes(data, position)
        if not will_topic then
            return nil, "will topic is incomplete"
        end
        local will_payload
        will_payload, position = read_bytes(data, position)
        if not will_payload then
            return nil, "will payload is incomplete"
        end
    end

    local username
    if has_username then
        username, position = read_bytes(data, position)
        if not username then
            return nil, "username is incomplete"
        end
    end

    local password
    if has_password then
        password, position = read_bytes(data, position)
        if not password then
            return nil, "password is incomplete"
        end
    end

    return {
        protocol_name = protocol_name,
        protocol_level = protocol_level,
        client_id = client_id,
        username = username,
        password = password,
    }
end

return M
