local security = require "browser_security"
local token_verifier = require "rs256_token"

local function unauthorized(message)
    ngx.status = ngx.HTTP_UNAUTHORIZED
    ngx.header["Content-Type"] = "application/json"
    ngx.say('{"error":"unauthorized","message":"' .. (message or "Unauthorized") .. '"}')
    return ngx.exit(ngx.HTTP_UNAUTHORIZED)
end

local function access_token()
    local auth = ngx.var.http_authorization
    if auth and auth ~= "" then
        local match = auth:match("^[Bb]earer%s+(.+)$")
        if match then return match end
    end

    local cookie_token = security.cookie_value("access_token")
    if cookie_token and cookie_token ~= "" then return cookie_token end

    return nil
end

if ngx.req.get_method() == "OPTIONS" then
    return
end

if not security.enforce_csrf() then
    return
end

local token = access_token()
if not token then
    return unauthorized("Missing access token")
end

local issuer = os.getenv("IDENTITY_JWT_ISSUER") or "account-service"
local audience = os.getenv("IDENTITY_JWT_AUDIENCE") or "sparrow"

local payload = token_verifier.verify(token)
if not payload then
    return unauthorized("Invalid bearer token")
end

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
local expires_at = tonumber(payload.exp)
if not expires_at or expires_at <= now then
    return unauthorized("Expired bearer token")
end

if not payload.sub or payload.sub == "" then
    return unauthorized("Token subject is required")
end

ngx.var.auth_client_id = payload.sub
ngx.var.auth_expires_at = tostring(expires_at)
