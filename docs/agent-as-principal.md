# Requirements
1. [Create and register a new agent](https://auth0.com/docs/ai-agents-mcp/agents-as-principal/register-an-agent#create-and-register-a-new-agent)
2. [Associate an existing M2M client to Agent](https://auth0.com/docs/ai-agents-mcp/agents-as-principal/associate-agent-client#associate-an-existing-client)
3. Resource server is granted to m2m client
4. [Configure resource server to receive agent subject claims](https://auth0.com/docs/ai-agents-mcp/agents-as-principal/agent-identity-in-tokens#configure-resource-server-to-receive-agent-subject-claims)


# Client Credentials Flow
```shell
./client-credentials.sh -c e7vvzxxxx -x xxx -a aap.rs
```

Resulting access_token:

```json
{
  "iss": "https://abbaspour.auth0.com/",
  "sub": "agt_kDN15WVy2ea5micNE6pueb",
  "aud": "aap.rs",
  "iat": 1787637869,
  "exp": 1787724269,
  "client_profile": "service ai_agent",
  "sub_profile": "ai_agent",
  "gty": "client-credentials",
  "azp": "e7vvzTr4OAj4aG7szr1WHvzqeS9OlpHw"
}
```

# Resource Owner Flows

## Redirect based Code/Implicit flow

```bash
./authorize.sh -a aap.rs -T token -C 
https://abbaspour.auth0.com/authorize?client_id=VJIEWAptlFWokl2pRC2ptswic1jCGoEC &
    response_type=token &
    nonce=mynonce &
    redirect_uri=http://local.abbaspour.net:1980/cgi-bin/cb.sh &
    scope=openid profile email &
    audience=aap.rs &
    state=mystate
```

Resulting access_token:
```json
	

{
  "iss": "https://abbaspour.auth0.com/",
  "sub": "auth0|5fadc2e53f6a96006f998832",
  "aud": [
    "aap.rs",
    "https://abbaspour.auth0.com/userinfo"
  ],
  "iat": 1787639099,
  "exp": 1787646299,
  "scope": "openid profile email",
  "act": {
    "sub": "agt_kDN15WVy2ea5micNE6pueb",
    "sub_profile": "ai_agent",
    "client_id": "VJIEWAptlFWokl2pRC2ptswic1jCGoEC",
    "iss": "https://abbaspour.auth0.com/"
  },
  "client_profile": "native_app ai_agent",
  "sub_profile": "user",
  "azp": "VJIEWAptlFWokl2pRC2ptswic1jCGoEC"
}
```