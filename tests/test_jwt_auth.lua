local cwd = os.getenv("PWD") or "."
package.path = "/gateway/lua/?.lua;" .. cwd .. "/gateway/lua/?.lua;" .. cwd .. "/lua/?.lua;" .. package.path

local verified_token = nil
package.preload["rs256_token"] = function()
    return {
        verify = function(token)
            verified_token = token
            if token ~= "cookie-token" and token ~= "bearer-token" then
                return nil
            end
            return {
                iss = "account-service",
                aud = "sparrow",
                exp = 200,
                sub = "client-id"
            }
        end
    }
end

local jwt_auth_path = cwd .. "/gateway/lua/jwt_auth.lua"
local jwt_auth_file = io.open(jwt_auth_path)
if not jwt_auth_file then
    jwt_auth_path = cwd .. "/lua/jwt_auth.lua"
else
    jwt_auth_file:close()
end

local last_exit = nil
ngx = {
    HTTP_FORBIDDEN = 403,
    HTTP_UNAUTHORIZED = 401,
    status = 200,
    header = {},
    var = {},
    req = {
        get_method = function() return "GET" end
    },
    say = function() end,
    exit = function(status) last_exit = status end,
    time = function() return 100 end
}

local function reset()
    last_exit = nil
    verified_token = nil
    ngx.status = 200
    ngx.header = {}
    ngx.var = {}
end

reset()
ngx.var.http_cookie = "access_token=cookie-token"
dofile(jwt_auth_path)
assert(last_exit == nil)
assert(verified_token == "cookie-token")
assert(ngx.var.auth_client_id == "client-id")
assert(ngx.var.auth_expires_at == "200")

reset()
ngx.var.http_authorization = "Bearer bearer-token"
ngx.var.http_cookie = "access_token=cookie-token"
dofile(jwt_auth_path)
assert(last_exit == nil)
assert(verified_token == "bearer-token")

reset()
ngx.var.arg_access_token = "cookie-token"
dofile(jwt_auth_path)
assert(last_exit == 403)
assert(verified_token == nil)

print("jwt_auth tests passed")
