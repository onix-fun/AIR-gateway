# Gateway

OpenResty gateway for HTTP/WebSocket routing and native MQTT connection authentication.

## Public ports

- HTTP: `8088`
- MQTT TCP: `1883`

## HTTP routing

- `/api/domain/*` -> `domain:8080/*`
- `/api/analytics/*` -> `analytics:8081/*`
- `/api/contacts/ws/*` -> `contacts-device-ws:8080/ws/*`

Account routes (`/api/auth`, `/api/users`, `/api/sessions`, `/api/search`, and
`/api/avatars`) are intentionally absent. They are public only through the
separate `account-gateway`.

Protected routes accept an RS256 JWT from `account-service` either as
`Authorization: Bearer <jwt>` or the browser-only HttpOnly `access_token` cookie.
Bearer auth takes precedence. The gateway reads only the public PEM and strips any incoming
`X-Client-Id` value and injects the JWT subject after validating issuer, audience, and expiry.
JWT query parameters are not supported.

Cookie-auth state changes require a trusted `Origin` plus an `X-CSRF-Token` header matching
the HttpOnly `csrf_token` cookie. CORS and WebSocket origins are restricted by
`SPARROW_TRUSTED_BASE_DOMAIN`, with an explicit localhost development allowlist.

## MQTT auth

MQTT clients connect with:

- username: consumer token
- password: optional token carrier for compatible clients

The gateway validates the token through `DOMAIN_TOKEN_VALIDATE_URL`, obtains the
`consumerId`, forwards it to Mosquitto as the upstream username, and returns it
to the device as the MQTT 5 CONNACK User Property `consumer_id`.
