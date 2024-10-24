# OIDC Bash
Bash script collection acting as OAuth2/OIDC Relying Party (RP).

# Design
Main purpose is education, hence, simplicity values over code reuse in this repo. 
For example `/token` endpoint is an overloaded endpoint that does many things. 
There are multiple scripts in this repo that communicate with token endpoint but for different flows.
You'll see some code duplicate all authenticating against token endpoint however each script does a certain flow.

# Supported Standards
## OAuth 2 Family
- [The OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749)
- [The OAuth 2.1 Authorization Framework](https://datatracker.ietf.org/doc/draft-ietf-oauth-v2-1/)
- [OAuth 2.0 Device Authorization Grant](https://datatracker.ietf.org/doc/html/rfc8628)
- [OAuth 2.0 Pushed Authorization Requests (PAR)](https://datatracker.ietf.org/doc/html/rfc9126)
- [OAuth 2.0 JWT-Secured Authorization Request (JAR)](https://datatracker.ietf.org/doc/html/rfc9101) 

## OIDC Family
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
