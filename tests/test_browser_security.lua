package.path = "/gateway/lua/?.lua;" .. (os.getenv("PWD") or ".") .. "/gateway/lua/?.lua;" .. package.path

local last_message = nil
local last_exit = nil

ngx = {
    HTTP_FORBIDDEN = 403,
    status = 200,
    header = {},
    var = {},
    req = {
        get_method = function() return "POST" end
    },
    say = function(message) last_message = message end,
    exit = function(status) last_exit = status end
}

local security = require "browser_security"

assert(security.is_allowed_origin("http://localhost:5173"))
assert(security.is_allowed_origin("https://127.0.0.1:5174"))
assert(not security.is_allowed_origin("https://localhost.evil.test"))
assert(not security.is_allowed_origin("https://evil.test"))

ngx.var.http_origin = "http://localhost:5173"
ngx.var.http_cookie = "csrf_token=expected"
ngx.var.http_x_csrf_token = "expected"
assert(security.enforce_csrf())

ngx.var.http_x_csrf_token = "wrong"
assert(not security.enforce_csrf())
assert(last_exit == 403)
assert(last_message:match("Valid CSRF token"))

ngx.var.http_authorization = "Bearer test"
assert(security.enforce_csrf())

print("browser_security tests passed")
