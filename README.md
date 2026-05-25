# Gateway

OpenResty gateway for HTTP/WebSocket routing and native MQTT connection authentication.

## Public ports

- HTTP: `8088`
- MQTT TCP: `1883`

## HTTP routing

- `/api/domain/*` -> `domain:8080/*`
- `/api/analytics/*` -> `analytics:8081/*`
- `/api/contacts/ws/*` -> `contacts-device-ws:8080/ws/*`

The gateway strips any incoming `X-Client-Id` value and injects `GATEWAY_STUB_CLIENT_ID`.

## MQTT auth

MQTT clients connect with:

- username: `consumerId`
- password: consumer token

The gateway validates the token through `DOMAIN_TOKEN_VALIDATE_URL` and proxies only valid connections to Mosquitto.
