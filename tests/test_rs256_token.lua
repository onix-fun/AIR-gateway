local cwd = os.getenv("PWD") or "."
package.path = "/gateway/lua/?.lua;" .. cwd .. "/gateway/lua/?.lua;" .. cwd .. "/lua/?.lua;" .. package.path

local verifier = require "rs256_token"
local token = assert(os.getenv("TEST_RS256_TOKEN"))
local payload, err = verifier.verify(token)
assert(payload, err)
assert(payload.iss == "account-service")
assert(payload.aud == "sparrow")
assert(payload.sub == "gateway-test")

local replacement = token:sub(-1) == "A" and "B" or "A"
local tampered_payload, tampered_error = verifier.verify(token:sub(1, -2) .. replacement)
assert(not tampered_payload)
assert(tampered_error)

print("RS256 token verification tests passed")
