local bit = require "bit"
package.path = "/gateway/lua/?.lua;" .. (os.getenv("PWD") or ".") .. "/gateway/lua/?.lua;" .. package.path

local parser = require "mqtt_parser"

local function assert_equal(actual, expected, message)
    if actual ~= expected then
        error((message or "assertion failed") .. ": expected " .. tostring(expected) .. ", got " .. tostring(actual), 2)
    end
end

local function assert_not_nil(value, message)
    if value == nil then
        error((message or "expected non-nil") .. ", got nil", 2)
    end
end

-- Test encode_remaining_length roundtrip
do
    local test_values = {0, 1, 127, 128, 16383, 16384, 2097151, 2097152, 268435455}
    for _, val in ipairs(test_values) do
        local encoded = parser.encode_remaining_length(val)
        local decoded, pos = parser.decode_remaining_length(encoded, 1)
        assert_equal(decoded, val, "encode/decode remaining length " .. val)
    end
    print("  encode_remaining_length roundtrip: OK")
end

-- Test encode_string
do
    local s1 = parser.encode_string("hello")
    assert_equal(#s1, 7, "encode_string 'hello' length")
    assert_equal(s1:byte(1), 0, "encode_string 'hello' msb")
    assert_equal(s1:byte(2), 5, "encode_string 'hello' lsb")

    local s2 = parser.encode_string("")
    assert_equal(#s2, 2, "encode_string empty length")
    assert_equal(s2:byte(1), 0, "encode_string empty msb")
    assert_equal(s2:byte(2), 0, "encode_string empty lsb")

    local s3 = parser.encode_string(nil)
    assert_equal(#s3, 2, "encode_string nil length")
    print("  encode_string: OK")
end

-- Test parse_connect existing behavior
do
    local remaining = parser.encode_string("MQTT") .. string.char(4, 0xC2, 0, 60)
        .. parser.encode_string("device-client")
        .. parser.encode_string("11111111-1111-1111-1111-111111111111")
        .. parser.encode_string("consumer-token")
    local raw = string.char(0x10) .. parser.encode_remaining_length(#remaining) .. remaining

    local parsed = assert(parser.parse_connect(raw))
    assert_equal(parsed.client_id, "device-client", "client id")
    assert_equal(parsed.username, "11111111-1111-1111-1111-111111111111", "username")
    assert_equal(parsed.password, "consumer-token", "password")
    assert_equal(parsed.protocol_level, 4, "protocol level")
    assert_equal(parsed.connect_flags, 0xC2, "connect flags")
    assert_equal(parsed.keep_alive, 60, "keep alive")
    print("  parse_connect MQTT 3.1.1: OK")
end

-- Test parse_connect MQTT 5.0
do
    local remaining = parser.encode_string("MQTT") .. string.char(5, 0x42, 0, 60, 0x00)
        .. parser.encode_string("device-client")
        .. parser.encode_string("consumer-token")
    local raw = string.char(0x10) .. parser.encode_remaining_length(#remaining) .. remaining

    local parsed = assert(parser.parse_connect(raw))
    assert_equal(parsed.protocol_level, 5, "MQTT 5 protocol level")
    assert_equal(parsed.client_id, "device-client", "MQTT 5 client id")
    assert_equal(parsed.connect_flags, 0x42, "MQTT 5 flags (password only)")
    assert_equal(parsed.connect_properties, "", "MQTT 5 empty properties")
    assert_equal(parsed.password, "consumer-token", "MQTT 5 password")
    assert_equal(parsed.username, nil, "MQTT 5 no username")
    print("  parse_connect MQTT 5.0: OK")
end

-- Test encode_connect roundtrip
do
    local fields = {
        protocol_name = "MQTT",
        protocol_level = 5,
        connect_flags = 0x42,
        keep_alive = 60,
        connect_properties = nil,
        client_id = "test-device",
        username = nil,
        password = "test-token",
        will_topic = nil,
        will_payload = nil,
        will_properties = nil,
    }
    local packet = parser.encode_connect(fields)
    local parsed = assert(parser.parse_connect(packet))
    assert_equal(parsed.protocol_level, 5, "encode_connect protocol level")
    assert_equal(parsed.client_id, "test-device", "encode_connect client id")
    assert_equal(parsed.password, "test-token", "encode_connect password")
    assert_equal(parsed.connect_flags, 0x42, "encode_connect flags")
    assert_equal(parsed.connect_properties, "", "encode_connect empty properties")
    assert_equal(parsed.keep_alive, 60, "encode_connect keep alive")
    print("  encode_connect roundtrip: OK")
end

-- Test encode_connect with username
do
    local fields = {
        protocol_name = "MQTT",
        protocol_level = 5,
        connect_flags = bit.bor(0x42, 0x80),
        keep_alive = 60,
        connect_properties = nil,
        client_id = "test-device",
        username = "550e8400-e29b-41d4-a716-446655440000",
        password = "test-token",
        will_topic = nil,
        will_payload = nil,
        will_properties = nil,
    }
    local packet = parser.encode_connect(fields)
    local parsed = assert(parser.parse_connect(packet))
    assert_equal(parsed.username, "550e8400-e29b-41d4-a716-446655440000", "encode_connect username")
    assert_equal(parsed.password, "test-token", "encode_connect with username password")
    assert_equal(parsed.client_id, "test-device", "encode_connect with username client id")
    print("  encode_connect with username: OK")
end

-- Test parse_connack MQTT 5.0
do
    -- MQTT 5.0 CONNACK: session_present=0, reason_code=0, properties length=0
    local raw = string.char(0x20, 0x03, 0x00, 0x00, 0x00)
    local parsed = assert(parser.parse_connack(raw))
    assert_equal(parsed.session_present, false, "connack session present")
    assert_equal(parsed.reason_code, 0, "connack reason code")
    assert_equal(parsed.properties, nil, "connack no properties")
    print("  parse_connack MQTT 5.0 no props: OK")
end

-- Test parse_connack with properties
do
    local props = string.char(0x26) .. parser.encode_string("consumer_id") .. parser.encode_string("550e8400-e29b-41d4-a716-446655440000")
    local props_length = #props
    local raw = string.char(0x20)
        .. parser.encode_remaining_length(2 + 1 + props_length)
        .. string.char(0x00, 0x00)
        .. parser.encode_remaining_length(props_length)
        .. props
    local parsed = assert(parser.parse_connack(raw))
    assert_equal(parsed.session_present, false, "connack with props session present")
    assert_equal(parsed.reason_code, 0, "connack with props reason code")
    assert_not_nil(parsed.properties, "connack with props should have properties")
    print("  parse_connack with properties: OK")
end

-- Test add_user_property and get_user_property roundtrip
do
    -- Start with CONNACK without properties
    local raw = string.char(0x20, 0x03, 0x00, 0x00, 0x00)
    local modified = parser.add_user_property(raw, "consumer_id", "550e8400-e29b-41d4-a716-446655440000")
    assert_not_nil(modified, "add_user_property should succeed")

    local value = parser.get_user_property(modified, "consumer_id")
    assert_equal(value, "550e8400-e29b-41d4-a716-446655440000", "add/get user property roundtrip")
    print("  add/get_user_property roundtrip: OK")
end

-- Test add_user_property appends to existing properties
do
    local existing_props = string.char(0x11, 0x00, 0x00, 0x00, 0x3C)
    local remaining = string.char(0x00, 0x00)
        .. parser.encode_remaining_length(#existing_props)
        .. existing_props
    local raw = string.char(0x20) .. parser.encode_remaining_length(#remaining) .. remaining
    local modified = parser.add_user_property(raw, "consumer_id", "550e8400-e29b-41d4-a716-446655440000")
    assert_not_nil(modified, "add_user_property with existing props")

    local value = parser.get_user_property(modified, "consumer_id")
    assert_equal(value, "550e8400-e29b-41d4-a716-446655440000", "get user property from appended props")
    print("  add_user_property to existing props: OK")
end

-- Test malformed packets
do
    local malformed, err = parser.parse_connect(string.char(0x30, 0x00))
    assert_equal(malformed, nil, "malformed packet")
    assert_not_nil(err, "expected malformed packet error")

    local malformed_connack, err2 = parser.parse_connack(string.char(0x20, 0x00))
    assert_equal(malformed_connack, nil, "malformed connack")
    assert_not_nil(err2, "expected malformed connack error")

    local incomplete_connack, err3 = parser.parse_connack(string.char(0x20, 0x03, 0x00, 0x00))
    assert_equal(incomplete_connack, nil, "incomplete connack")
    assert_not_nil(err3, "expected incomplete connack error")
    print("  malformed packet handling: OK")
end

print("mqtt_parser all tests passed")
