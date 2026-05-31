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
    local keep_alive = data:byte(position + 2) * 256 + data:byte(position + 3)
    position = position + 4 -- protocol level, flags, keepalive msb/lsb

    local connect_properties = ""
    if protocol_level == 5 then
        local properties_length, next_position, properties_err = M.decode_remaining_length(data, position)
        if properties_err then
            return nil, properties_err
        end
        if next_position + properties_length - 1 > #data then
            return nil, "connect properties are incomplete"
        end
        if properties_length > 0 then
            connect_properties = data:sub(next_position, next_position + properties_length - 1)
        end
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

    local will_topic = nil
    local will_payload = nil
    local will_properties = ""

    if has_will then
        if protocol_level == 5 then
            local wp_len
            wp_len, position = M.decode_remaining_length(data, position)
            if not wp_len or position + wp_len - 1 > #data then
                return nil, "will properties are incomplete"
            end
            if wp_len and wp_len > 0 then
                will_properties = data:sub(position, position + wp_len - 1)
                position = position + wp_len
            end
        end
        will_topic, position = read_bytes(data, position)
        if not will_topic then
            return nil, "will topic is incomplete"
        end
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
        connect_flags = connect_flags,
        keep_alive = keep_alive,
        connect_properties = connect_properties,
        client_id = client_id,
        username = username,
        password = password,
        will_topic = will_topic,
        will_payload = will_payload,
        will_properties = will_properties,
    }
end

function M.encode_remaining_length(value)
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

function M.encode_string(value)
    if not value then
        return string.char(0x00, 0x00)
    end
    return string.char(math.floor(#value / 256), #value % 256) .. value
end

function M.encode_connect(p)
    local variable_header = M.encode_string(p.protocol_name or "MQTT")
        .. string.char(p.protocol_level)
        .. string.char(p.connect_flags)
        .. string.char(math.floor(p.keep_alive / 256), p.keep_alive % 256)

    if p.protocol_level == 5 then
        local props_raw = p.connect_properties or ""
        variable_header = variable_header .. M.encode_remaining_length(#props_raw) .. props_raw
    end

    local payload = M.encode_string(p.client_id)

    if bit.band(p.connect_flags, 0x04) ~= 0 then
        if p.protocol_level == 5 then
            local wp = p.will_properties or ""
            payload = payload .. M.encode_remaining_length(#wp) .. wp
        end
        payload = payload .. M.encode_string(p.will_topic)
        payload = payload .. M.encode_string(p.will_payload)
    end

    if bit.band(p.connect_flags, 0x80) ~= 0 then
        payload = payload .. M.encode_string(p.username)
    end

    if bit.band(p.connect_flags, 0x40) ~= 0 then
        payload = payload .. M.encode_string(p.password)
    end

    local remaining = variable_header .. payload
    local packet = string.char(0x10) .. M.encode_remaining_length(#remaining) .. remaining
    return packet
end

function M.parse_connack(data)
    if #data < 4 then
        return nil, "packet too short for CONNACK"
    end
    if data:byte(1) ~= 0x20 then
        return nil, "not a CONNACK packet"
    end

    local remaining_length, payload_pos = M.decode_remaining_length(data, 2)
    if not remaining_length then
        return nil, "invalid remaining length"
    end
    if #data < payload_pos + remaining_length - 1 then
        return nil, "CONNACK packet is incomplete"
    end

    local position = payload_pos
    local session_present = bit.band(data:byte(position), 0x01) ~= 0
    local reason_code = data:byte(position + 1)
    position = position + 2

    local properties = nil
    if remaining_length > 2 then
        local prop_length
        prop_length, position = M.decode_remaining_length(data, position)
        if prop_length and prop_length > 0 then
            properties = data:sub(position, position + prop_length - 1)
        end
    end

    return {
        session_present = session_present,
        reason_code = reason_code,
        properties = properties,
    }
end

function M.add_user_property(data, key, value)
    if #data < 1 then
        return nil, "empty packet"
    end

    local remaining_length, payload_pos = M.decode_remaining_length(data, 2)
    if not remaining_length then
        return nil, "invalid remaining length"
    end

    if remaining_length < 3 then
        return nil, "not an MQTT 5.0 CONNACK (no properties field)"
    end

    local new_prop = string.char(0x26)
        .. M.encode_string(key)
        .. M.encode_string(value)

    local variable_header = data:sub(payload_pos, payload_pos + 1)

    local old_prop_length, prop_end = M.decode_remaining_length(data, payload_pos + 2)
    if not old_prop_length then
        return nil, "invalid property length in CONNACK"
    end

    local old_props = ""
    if old_prop_length > 0 then
        old_props = data:sub(prop_end, prop_end + old_prop_length - 1)
    end

    local new_prop_length = old_prop_length + #new_prop
    local new_props = M.encode_remaining_length(new_prop_length) .. old_props .. new_prop

    local new_remaining = variable_header .. new_props
    local new_remaining_length = #new_remaining
    local header = data:sub(1, 1)

    return header .. M.encode_remaining_length(new_remaining_length) .. new_remaining
end

-- Extract User Property value by key from CONNACK properties
function M.get_user_property(data, key)
    local connack, err = M.parse_connack(data)
    if not connack or not connack.properties then
        return nil
    end

    local props = connack.properties
    local pos = 1
    while pos <= #props do
        local id = props:byte(pos)
        pos = pos + 1
        if id == 0x26 then
            local k, next_pos = M._read_bytes(props, pos)
            if not k then break end
            pos = next_pos
            if k == key then
                local v
                v, _ = M._read_bytes(props, pos)
                return v
            end
            local vv
            vv, next_pos = M._read_bytes(props, pos)
            if not vv then break end
            pos = next_pos
        elseif id == 0x12 or id == 0x15 or id == 0x16 or id == 0x1A or id == 0x1C or id == 0x1F then
            local property_value, next_pos = M._read_bytes(props, pos)
            if not property_value then break end
            pos = next_pos
        elseif id == 0x11 or id == 0x27 then
            pos = pos + 4
        elseif id == 0x13 or id == 0x21 or id == 0x22 then
            pos = pos + 2
        elseif id == 0x24 or id == 0x25 or id == 0x28 or id == 0x29 or id == 0x2A then
            pos = pos + 1
        else
            break
        end
    end
    return nil
end

function M._read_bytes(data, position)
    return read_bytes(data, position)
end

return M
