# OIDC Bash
Bash script collection acting as OAuth2/OIDC Relying Party (RP).

# Design
Main purpose is education, hence, simplicity values over code reuse in this repo. 
For example `/token` endpoint is an overloaded endpoint that does many things. 
There are multiple scripts in this repo that communicate with token endpoint but for different flows.
You'll see some code duplicate all authenticating against token endpoint however each script does a certain flow.

# Supported Standards
## OAuth 2 Family
- [The OAuth 2.0 Authorization Framework - RFC-6749](https://datatracker.ietf.org/doc/html/rfc6749)
- [The OAuth 2.1 Authorization Framework](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)
- [OAuth 2.0 Device Authorization Grant - RFC-8628](https://datatracker.ietf.org/doc/html/rfc8628)
- [OAuth 2.0 Pushed Authorization Requests (PAR) - RFC-9126](https://datatracker.ietf.org/doc/html/rfc9126)
- [OAuth 2.0 JWT-Secured Authorization Request (JAR) - RFC-9101](https://datatracker.ietf.org/doc/html/rfc9101) 
- [OAuth 2.0 Demonstrating Proof-of-Possession at the Application Layer (DPoP) - RFC-9449](https://datatracker.ietf.org/doc/html/rfc9449)
- [OAuth 2.0 Token Exchange - RFC-8693](https://datatracker.ietf.org/doc/html/rfc8693)
- [OAuth 2.0 JSON Web Token (JWT) Profile for Client Authentication and Authorization Grants - RFC-7523](https://datatracker.ietf.org/doc/html/rfc7523)
- [Identity Assertion JWT Authorization Grant (ID-JAG)](https://datatracker.ietf.org/doc/draft-ietf-oauth-identity-assertion-authz-grant/)

## OIDC Family
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [CIBA - Core 1.0](https://openid.net/specs/openid-client-initiated-backchannel-authentication-core-1_0.html)

# Scripts

| Script                                                 | Description                                                                                                                     |
|--------------------------------------------------------|---------------------------------------------------------------------------------------------------------------------------------|
| [`authorize.sh`](./authorize.sh)                       | Initiates the Authorization Code flow by building an `/authorize` URL (supports PKCE, PAR, JAR) and opening it in the browser.  |
| [`code-exchange.sh`](./code-exchange.sh)               | Exchanges an authorization code for tokens at the `/token` endpoint (supports PKCE, DPoP, private key JWT, Device Code, CIBA).  |
| [`client-credentials.sh`](./client-credentials.sh)     | Performs the Client Credentials grant for machine-to-machine access tokens (supports client secret, private key JWT, mTLS).     |
| [`device-flow.sh`](./device-flow.sh)                   | Initiates the OAuth 2.0 Device Authorization Grant (RFC 8628) and returns a user code and verification URI.                     |
| [`refresh.sh`](./refresh.sh)                           | Uses a refresh token to obtain a new access token (supports DPoP and scope/audience downscoping).                               |
| [`resource-owner.sh`](./resource-owner.sh)             | Performs the Resource Owner Password Credentials grant (legacy ROPG flow).                                                      |
| [`token-exchange.sh`](./token-exchange.sh)             | Performs OAuth 2.0 Token Exchange (RFC 8693) to swap one token for another.                                                     |
| [`revoke-refresh-token.sh`](./revoke-refresh-token.sh) | Revokes a refresh token via the `/oauth/revoke` endpoint.                                                                       |
| [`logout.sh`](./logout.sh)                             | Performs RP-Initiated Logout via `/oidc/logout` (or federated/SAML logout variants).                                            |
| [`callback.sh`](./callback.sh)                         | Minimal `redirect_uri` listener (netcat-based) that renders incoming query parameters as an HTML key-value table and to stdout. |
