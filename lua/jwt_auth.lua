local jwt = require "resty.jwt"

local function unauthorized(message)
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header["Content-Type"] = "application/json"
    ngx.say('{"error":"unauthorized","message":"' .. (message or "Unauthorized") .. '"}')
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

local function bearer_token()
    local auth = ngx.var.http_authorization
    if auth and auth ~= "" then
        local match = auth:match("^[Bb]earer%s+(.+)$")
        if match then return match end
    end

    local arg_token = ngx.var.arg_access_token
    if arg_token and arg_token ~= "" then return arg_token end

    return nil
end

if ngx.req.get_method() == "OPTIONS" then
    return
end

local token = bearer_token()
if not token then
    return unauthorized("Missing bearer token")
end

local secret = os.getenv("IDENTITY_JWT_SECRET") or "change-me"
local issuer = os.getenv("IDENTITY_JWT_ISSUER") or "identity-service"
local audience = os.getenv("IDENTITY_JWT_AUDIENCE") or "gateway"

local jwt_obj = jwt:verify(secret, token)
if not jwt_obj or not jwt_obj.verified then
    return unauthorized("Invalid bearer token")
end

local payload = jwt_obj.payload or {}
if payload.iss ~= issuer then
    return unauthorized("Invalid token issuer")
end

local aud = payload.aud
local audience_ok = aud == audience
if type(aud) == "table" then
    for _, value in ipairs(aud) do
        if value == audience then
            audience_ok = true
            break
        end
    end
end
if not audience_ok then
    return unauthorized("Invalid token audience")
end

local now = ngx.time()
if payload.exp and tonumber(payload.exp) and tonumber(payload.exp) < now then
    return unauthorized("Expired bearer token")
end

if not payload.sub or payload.sub == "" then
    return unauthorized("Token subject is required")
end

ngx.var.auth_client_id = payload.sub
