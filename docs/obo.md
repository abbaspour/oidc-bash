# Setup Clients and Resource Servers

```terraform
resource "auth0_resource_server" "obo" {
  identifier = "https://test-obo-api.com"
  name = "My OBO Test API"

  skip_consent_for_verifiable_first_party_clients = true
}

resource "auth0_resource_server_scopes" "obo" {
  resource_server_identifier = auth0_resource_server.obo.identifier

  scopes {
    name = "read:item"
  }
}

output "obo-client-id" {
  value = auth0_resource_server.obo.client_id
}

resource "auth0_client" "obo" {
  name = "My OBO Test API client (tf)"
  app_type = "resource_server"
  resource_server_identifier = auth0_resource_server.obo.identifier

  token_exchange {
    allow_any_profile_of_type = ["on_behalf_of_token_exchange"]
  }
}

resource "auth0_client_grant" "obo" {
  audience = auth0_resource_server.obo.identifier
  client_id = auth0_client.obo.client_id
  subject_type = "user"
  scopes = [
    "read:item"
  ]
}

resource "auth0_resource_server" "downstream" {
  identifier = "urn:downstream:api"
  name = "My Downstream API"
  skip_consent_for_verifiable_first_party_clients = true
}

resource "auth0_resource_server_scopes" "downstream" {
  resource_server_identifier = auth0_resource_server.downstream.identifier

  scopes {
    name = "read:private"
  }
}
```

# Authenticate with External Facing API

```bash
./authorize.sh  -T token -a https://test-obo-api.com -s read:item -C

export client_id="output from TF auth0_resource_server.obo.client_id"
export access_token='xxxx'
```

```json
{
  "iss": "https://abbaspour.auth0.com/",
  "sub": "auth0|5fadc2e53f6a96006f998832",
  "aud": "https://test-obo-api.com",
  "iat": 1785813160,
  "exp": 1785820360,
  "scope": "read:item",
  "azp": "VJIEWAptlFWokl2pRC2ptswic1jCGoEC"
}
```
# Exchange External Audience to Internal with TE


```bash
./token-exchange.sh  -t abbaspour -c $client_id -x $client_secret \
 -i $access_token -u access_token -U access_token \
 -a "urn:downstream:api" -s "read:private"
```

```json
{
  "iss": "https://abbaspour.auth0.com/",
  "sub": "auth0|5fadc2e53f6a96006f998832",
  "aud": "urn:downstream:api",
  "iat": 1785813799,
  "exp": 1785900199,
  "scope": "read:private",
  "act": {
    "sub": "4nci5vb0q9HQzYCExRn4mVGhCtJU7171",
    "act": {
      "sub": "VJIEWAptlFWokl2pRC2ptswic1jCGoEC"
    }
  },
  "azp": "4nci5vb0q9HQzYCExRn4mVGhCtJU7171"
}
```