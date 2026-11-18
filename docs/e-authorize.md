# Auth0 Embedded Authorize (`/e/authorize`)

Auth0's vendor-specific profile of [OAuth 2.0 for First-Party Applications](https://datatracker.ietf.org/doc/draft-ietf-oauth-first-party-apps/).
A first-party client runs sign-in in its own UI, without a browser redirect to Universal Login:

1. **Start**: `POST /e/authorize` with client credentials, connection, and the `capabilities` (actions) the client can display.
2. **Continue**: Auth0 answers `403 insufficient_authorization` with a new `auth_session` and a `next` list of allowed actions.
   The client sends one of them (with the newest `auth_session` and `client_id`), and the loop repeats.
3. **Finish**: Auth0 answers `200 {"authorization_code": "..."}`. The code is exchanged at `/oauth/token` with [`code-exchange.sh`](../code-exchange.sh).

> [!NOTE]
> Embedded Authorize is in Beta. It must be enabled per tenant and per application by Auth0. Response shapes, errors and limits can change.
> Beta supports email OTP as first factor, followed by MFA (TOTP, recovery code, email, SMS/voice).

## Prerequisites
- Non-production tenant with Embedded Authorize enabled for the tenant and the application.
- Database connection enabled for the application, with the email OTP authentication method turned on.

## Interactive
[`e-authorize.sh`](../e-authorize.sh) runs the loop, prompting on the terminal for each step in `next`. When `next` has more than
one entry (e.g. MFA factors) it shows a menu. Prompts go to stderr, so stdout carries only JSON.

```bash
./e-authorize.sh -t amin01@au -c ${client_id} -x ${client_secret} -r ${connection} -T
next: action:identify:email:v1
> email: jane@example.com
next: action:challenge:email:v1 j***@e***.com
next: action:verify:otp:v1 channel=email j***@e***.com
> otp (oob, email): 012345
next:
  [1] action:verify:otp:v1 type=totp
  [2] action:verify:recovery-code:v1
> choose [1-2]: 1
> otp (totp): 654321
{ "access_token": "...", "id_token": "...", ... }
```

- `-T` hands the code to `code-exchange.sh` (with `-u ''`, since there is no `redirect_uri` in this flow). Without `-T` it prints `{"authorization_code": "..."}`.
- `-v` prints every request and response, including `auth_session`. Treat `auth_session` as a secret.
- `-H email` prefills the email prompt.
- `-C capability` (repeatable) replaces the default capabilities, which are all actions the beta supports.
- `-E key=value` (repeatable) adds extra parameters to the start request.
- `invalid_code` re-prompts the same step. Other errors stop the script with a hint (see [Responses](#responses)).

The ID token's `amr` claim records how the user authenticated:
```bash
./jwt/decode-jws.sh "${id_token}" | jq .amr
```

## Single step
Mirrors the raw API, one request per call. Each call prints the response to stdout, and the HTTP status to stderr.
Exit code is `0` for `200` and `403 insufficient_authorization` (progress), `1` otherwise.

```bash
# 1. start
export AUTH_SESSION=$(./e-authorize.sh -t amin01@au -c ${client_id} -x ${client_secret} -r ${connection} -A start | jq -r .auth_session)

# 2. identify
export AUTH_SESSION=$(./e-authorize.sh -t amin01@au -c ${client_id} -S "${AUTH_SESSION}" -A action:identify:email:v1 -f email=jane@example.com | jq -r .auth_session)

# 3. send the code to email, index from next[]
export AUTH_SESSION=$(./e-authorize.sh -t amin01@au -c ${client_id} -S "${AUTH_SESSION}" -A action:challenge:email:v1 -f index=0 | jq -r .auth_session)

# 4. verify the code
./e-authorize.sh -t amin01@au -c ${client_id} -S "${AUTH_SESSION}" -A action:verify:otp:v1 -f type=oob -f otp=123456

# 5. exchange, without redirect_uri
./code-exchange.sh -t amin01@au -c ${client_id} -x ${client_secret} -u '' -a ${authorization_code}
```

`-f` values are sent as strings, except `index`, which is sent as a number.

## Actions
| Action                            | Fields                                          | Beta              |
|-----------------------------------|-------------------------------------------------|-------------------|
| `action:identify:email:v1`        | `email`                                         | Available         |
| `action:challenge:email:v1`       | `index`                                         | Available         |
| `action:challenge:phone:v1`       | `index`, `delivery_method` (`text` or `voice`)  | Available         |
| `action:verify:otp:v1`            | `otp`, `type` (`oob` email/SMS/voice, `totp`)   | Available         |
| `action:verify:recovery-code:v1`  | `code`; response carries replacement `new_code` | Available         |
| `action:confirm:recovery-code:v1` | none; confirms user saved `new_code`            | Available         |
| `action:challenge:push:v1`        | `index`                                         | Not yet available |
| `action:verify:oob:v1`            | none                                            | Not yet available |

Auth0 offers a second factor only when its action is declared in `capabilities` and the user has enrolled that factor.

## Responses
| Response                                          | Meaning                                                          |
|---------------------------------------------------|------------------------------------------------------------------|
| `403 insufficient_authorization` + `next`         | Another step is required. Send one of `next` with new `auth_session`. |
| `403 invalid_code` / `invalid_identifier_or_code` | Wrong code or identifier. Retry, up to the attempt limit.        |
| `403 access_denied`                               | Flow cannot continue (attempts exhausted, no eligible factor, `consent_required`). Start again. |
| `403 unauthorized_client`                         | Not enabled for this application.                                |
| `401 invalid_client`                              | Unknown client or wrong secret.                                  |
| `400 invalid_grant`                               | `auth_session` expired (15 min), invalid, or for another `client_id`. Start again. |
| `400 invalid_request`                             | Malformed `auth_session`, or action not in current `next`.       |
| `404`                                             | Not enabled for this tenant.                                     |
| `429`                                             | Rate limited.                                                    |
| `501 not_implemented`                             | Declared action not implemented in the beta.                     |
| `200 authorization_code`                          | Done. Exchange at `/oauth/token`.                                |

A wrong email and a wrong code produce the same response, so the client can't tell them apart. An email with no account gets the same responses, but no code is sent.

## Beta limitations
- No social/enterprise federation, third party applications or consent screens.
- Tenant Attack Protection settings might not apply during the beta.
