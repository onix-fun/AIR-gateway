local cjson = require "cjson.safe"
local pkey = require "resty.openssl.pkey"

local _M = {}
local cached_key = nil
local cached_key_path = nil

local function decode_base64url(value)
    local encoded = value:gsub("-", "+"):gsub("_", "/")
    local remainder = #encoded % 4
    if remainder > 0 then
        encoded = encoded .. string.rep("=", 4 - remainder)
    end
    return ngx.decode_base64(encoded)
end

local function public_key()
    local path = os.getenv("IDENTITY_JWT_PUBLIC_KEY_PATH") or "/run/secrets/account-jwt-public.pem"
    if cached_key and cached_key_path == path then
        return cached_key
    end

    local file = io.open(path, "r")
    if not file then
        return nil, "JWT public key is unavailable"
    end
    local pem = file:read("*a")
    file:close()

    local key, err = pkey.new(pem)
    if not key then
        return nil, "JWT public key is invalid: " .. (err or "unknown error")
    end

    cached_key = key
    cached_key_path = path
    return key
end

function _M.verify(token)
    local encoded_header, encoded_payload, encoded_signature = token:match("^([^.]+)%.([^.]+)%.([^.]+)$")
    if not encoded_header then
        return nil, "Malformed JWT"
    end

    local header = cjson.decode(decode_base64url(encoded_header) or "")
    if not header or header.alg ~= "RS256" then
        return nil, "JWT alg must be RS256"
    end

    local payload = cjson.decode(decode_base64url(encoded_payload) or "")
    local signature = decode_base64url(encoded_signature)
    if not payload or not signature then
        return nil, "Malformed JWT payload"
    end

    local key, key_error = public_key()
    if not key then
        return nil, key_error
    end

    local verified, verify_error = key:verify(signature, encoded_header .. "." .. encoded_payload, "sha256")
    if not verified then
        return nil, verify_error or "Invalid JWT signature"
    end

    return payload
end

return _M
