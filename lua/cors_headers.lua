local security = require "browser_security"
local origin = ngx.var.http_origin

if security.is_allowed_origin(origin) then
    ngx.header["Access-Control-Allow-Origin"] = origin
    ngx.header["Access-Control-Allow-Credentials"] = "true"
    ngx.header["Access-Control-Allow-Methods"] = "GET,POST,PUT,PATCH,DELETE,OPTIONS"
    ngx.header["Access-Control-Allow-Headers"] = "Content-Type,Authorization,X-Correlation-Id,X-CSRF-Token"
    ngx.header["Access-Control-Max-Age"] = "86400"
    ngx.header["Vary"] = "Origin"
end
