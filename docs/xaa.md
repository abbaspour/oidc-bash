# OIDC Setup

Follow Auth0 XAA setup guide [here](https://auth0.com/docs/secure/call-apis-on-users-behalf/xaa).

## Setup 1 - Setup Federation Between Auth0 (SP) and Okta (IdP)

### Setup 1a - Okta IdP OIDC App (Todo0) 
Create a OIDC App in Okta. Use XAA Resource App template from App Catalog. **Your redirect URI** is Auth0 domain `/login/callback`

![Okta Workforce Connection OpenID Client](./images/xaa-1a-okta-wf-client.png)

### Setup 1b - Auth0 SP
Create Okta Workforce Connection in Auth0. Named it `xaa-idp` for this demo.

![Auth0 Okta Connection](./images/xaa-1b-wf-connection.png)

Use **Client ID** and **Client secret** from 1a.

![Auth0 Okta Connection Credentials](./images/xaa-1b-wf-credentials.png)

Turn on **Resource Application** under **Cross App Access**.

![Auth0 Okta Connection Resource Application](./images/xaa-1b-wf-resource-app.png)

## Setup 2 - Create Resource in Auth0
Under Applications > APIs, with **Identifier** `urn:todo0:api`

![Auth0 Resource](./images/xaa-2-resource.png)

## Step 3 - Create Requesting App (Agent0) in Auth0
Under Applications > Applications, create a confidential regular web application client.

![Auth0 Requesting Application](./images/xaa-3-auth0-req-app.png)

with **Allowed Callback URLs** including `http://localhost:1980/cgi-bin/cb.sh`

![Auth0 Requesting Application Callback](./images/xaa-3-auth0-req-app-cb.png)

Connected to Okta Workforce Connection from step 1b.

![Auth0 Requesting Application Connections](./images/xaa-3-auth0-req-connection.png)

## Step 4 -  Create Requesting App (Agent0) in Okta
Use XAA Resource App template from App Catalog. 
Under **App Settings** set **Client ID** to Auth0 Requesting app client_id from step 3.

![Okta Requesting App](./images/xaa-4-okta-req-app.png)

Under **Manage Connections** connect this app to `Todo0` from Step 1.

![Okta Requesting App Connection](./images/xaa-4-okta-connection.png)

## Setup 5 - Assign Connection (Todo0) and Requesting (Agent0) Apps to User(s) in Okta
![Assign App to User(s)](./images/xaa-5-user-assignment.png)

# Testing

## Step 0 - Environment Variables

Assign environment variables.

```bash
export connection='okta-integrator'                    # Okta connection in Auth0 - step step 1 

export auth0_domain='amin.jp.auth0.com'
export client_id='Josz8cBBCWKA6Q7CkhyhYjbKY4hqjXMG'    # Agent0 Request app in Auth0 - step step 3
export client_secret="xxx-xxxx"                        # Agent0 in Auth0 - step step 3

export okta_domain='integrator-4598441.okta.com'
export agent_app_id='wlp159l03ysVKZlzt698'              
export req_app_id='0oa15duskmnhzdvvJ698'              # Agent0 in Okta - setup step 4 
export req_app_secret="xV1Lmtvihlv2iG6xJJ-xx"         # Agent0 in Okta - setup step 4
```

Run callback.sh to start listening.

```bash
./web/server.sh
```

## Step 1 - Federate from Auth0 to Okta to provision Federated User (one time only)
```bash
./authorize.sh -d $auth0_domain -c $client_id -r $connection -u http://localhost:1980/cgi-bin/cb.sh -C 
```
Open the browser, paste the URL from clipboard and login with one of the users assigned to the app in setup step 5.
![okta login](./images/xaa-demo-01.png)

Once login is successful, user is provisioned in Auth0.
![callback](./images/xaa-demo-02.png)
![profile](./images/xaa-demo-03.png)

## Step 2 - Get id_token from Okta with Requesting App (agent0)

```bash

./authorize.sh -d $okta_domain -c $req_app_id -u http://localhost:1980/cgi-bin/cb.sh -C

export id_token='....'
```

Sample id_token from Okta will look like this:

```json
{
  "sub": "00u14j584jskYLAVs698",
  "name": "Test XAA",
  "locale": "en_US",
  "email": "test-xaa@example.com",
  "ver": 1,
  "iss": "https://integrator-4598441.okta.com",
  "aud": "0oa15duskmnhzdvvJ698",
  "iat": 1784527202,
  "exp": 1784530802,
  "jti": "ID.AAleSpOCaxiaNY7u30iwdQ1jHcO6_CM3t4Ww2fXQKGo",
  "amr": [
    "pwd"
  ],
  "idp": "00o14ebpcyuYvL2Yi698",
  "nonce": "mynonce",
  "preferred_username": "test-xaa@example.com",
  "given_name": "Test",
  "family_name": "XAA",
  "zoneinfo": "America/Los_Angeles",
  "updated_at": 1784512921,
  "email_verified": true,
  "auth_time": 1784527037
}
```

### Step 3 - Request ID-JAG using id_token

#### OIDC
```bash
./token-exchange.sh -d $okta_domain -c $agent_app_id -k 89799ce500e455d5efdb96f24f93c836 -K xaa2/okta-agent-priv.pem \
  -i $id_token -a https://$auth0_domain/ -s read -p -J

export id_jag=$(./token-exchange.sh -d $okta_domain -c $agent_app_id -k 89799ce500e455d5efdb96f24f93c836 -K xaa2/okta-agent-priv.pem \
  -i $id_token -a https://$auth0_domain/ -s read -p -J | jq -r .access_token)
```

#### SAML
./token-exchange.sh -d $okta_domain -c $agent_app_id -k $kid -K xaa-saml1/okta-agent-priv.pem \
-i $saml -a https://$auth0_domain/ -s read -p -J

Here is a sample full payload of an exchange result 
```json  
{
  "token_type": "N_A",
  "expires_in": 300,
  "access_token": "eyJraWQiOiJFeEwySVlfaFdvdWhVeVNTUHVKZlI0U1hIaWdOdFNWVjB2RzlyN1F1N2ZRIiwidHlwIjoib2F1dGgtaWQtamFnK2p3dCIsImFsZyI6IlJTMjU2In0.eyJqdGkiOiJJREFBRy5ZMGZyd3hpT3k1dW9mbnM3amM5S2VTVG00NmFDTndlUkhLZl84RXd6SjV3IiwiaXNzIjoiaHR0cHM6Ly9pbnRlZ3JhdG9yLTQ1OTg0NDEub2t0YS5jb20iLCJhdWQiOiJodHRwczovL2FtaW4uanAuYXV0aDAuY29tLyIsImlhdCI6MTc4NDUyNzI3NiwiZXhwIjoxNzg0NTI3NTc2LCJzdWIiOiIwMHUxNGo1ODRqc2tZTEFWczY5OCIsImVtYWlsIjoidGVzdC14YWFAZXhhbXBsZS5jb20iLCJjbGllbnRfaWQiOiJKb3N6OGNCQkNXS0E2UTdDa2h5aFlqYktZNGhxalhNRyIsInN1Yl9wcm9maWxlIjoidXNlciIsInNjb3BlIjoicmVhZCIsImFjdCI6eyJzdWIiOiJ3bHAxNWR2N2M5OFhWUVlkMjY5OCIsInN1Yl9wcm9maWxlIjoiYWlfYWdlbnQiLCJhY3QiOnsic3ViIjoiMG9hMTVkdXNrbW5oemR2dko2OTgiLCJzdWJfcHJvZmlsZSI6IndlYl9hcHAifX19.ApZvVMAsZHAVrjllHga3qM1jLcGlQRu1QUkc0dZR3pMChr9pc1B5azW-DumswaJyZvogW5K5a-vZzZF21Br6AE2GOuSHd6GQ2SGB4Yjc4tajSf1gfnvX_4Y4upkw0yHKcxwC1EYx9ujFl8sLWxWVC4uU8SvzHuSCXMQqNGIMMxlrfXcgbCOYeIHhoAFu1jA2mSPU-haf7LH2oDN7YtnM8ouV8-4BBKAp0SHWjEg3ig5GHecomiwoWYTWJWVRYZhuFrt6c_PpgMmoQU5xnD6WcYeobkcacfpUeN433n4Tlh5onM8Hly1GzQ_rP6gpSsHc_geMmrVmv1F__IBNatCOJA",
  "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag"
}
```  

And here is a sample decoded ID-JAG JWT

```json
{
  "jti": "IDAAG.kufb35qQKxg8YkOGZKR0lvkr4Y9ygQ_hH6tD1iagmLY",
  "iss": "https://integrator-4598441.okta.com",
  "aud": "https://amin.jp.auth0.com/",
  "iat": 1784527782,
  "exp": 1784528082,
  "sub": "00u14j584jskYLAVs698",
  "email": "test-xaa@example.com",
  "client_id": "Josz8cBBCWKA6Q7CkhyhYjbKY4hqjXMG",
  "sub_profile": "user",
  "scope": "read",
  "act": {
    "sub": "wlp15dv7c98XVQYd2698",
    "sub_profile": "ai_agent",
    "act": {
      "sub": "0oa15duskmnhzdvvJ698",
      "sub_profile": "web_app"
    }
  }
}
```

### Step 4 - Request access_token using ID-JAG

```bash
./token-exchange.sh -d $auth0_domain -c $client_id -x $client_secret -G jwt-bearer -s read -A $id_jag -r urn:todo0:api
```

Produced following access_token:

```json
{
  "iss": "https://amin.jp.auth0.com/",
  "sub": "okta|okta-integrator|00u14j584jskYLAVs698",
  "aud": "urn:todo0:api",
  "iat": 1784527976,
  "exp": 1784614376,
  "scope": "read",
  "jti": "sLBjTu49HWt8WCUCyUuonr",
  "client_id": "Josz8cBBCWKA6Q7CkhyhYjbKY4hqjXMG"
}
```

# SAML Setup
```shell
export connection='okta-saml'                     

export auth0_domain='amin.jp.auth0.com'
export client_id='Josz8cBBCWKA6Q7CkhyhYjbKY4hqjXMG'    
export client_secret="fIoC5BkLQ5NontkcTojvyREhekP-tPiN_eefrCOQGmsnK2qAwSO0pQkp71or0qzg"                        

export okta_domain='integrator-4598441.okta.com'
export agent_app_id='wlp15fk3702lJwVLG698'              

export kid='1f8e5a2320115cfd3b783d1a60d93b67'     
export private_key="./xaa-saml2/okta-agent-priv.pem"

export saml='....'     
```

## SAML to refresh_token
```shell
./token-exchange.sh -d $okta_domain -c $agent_app_id -k $kid -K $private_key -i $saml -a https://$auth0_domain/ -s openid,offline_access -p -J -u saml2 -U refresh_token -v

export refresh_token=$(./token-exchange.sh -d $okta_domain -c $agent_app_id -k $kid -K $private_key -i $saml -a https://$auth0_domain/ -s openid,offline_access -p -J -u saml2 -U refresh_token | jq -r .access_token)
```

```json
{
  "token_type": "N_A",
  "expires_in": 2592000,
  "access_token": "4SsoXJDBgcq0uzMCqJCGzMVV9DPPsjYn2K-p5l_GCdo",
  "scope": "openid offline_access",
  "issued_token_type": "urn:ietf:params:oauth:token-type:refresh_token"
}
```

```shell
export refresh_token='xxx'

./token-exchange.sh -d $okta_domain -c $agent_app_id -k $kid -K $private_key -i $refresh_token -a https://$auth0_domain/ -s read -p -J -u refresh_token -v

export id_jag=$(./token-exchange.sh -d $okta_domain -c $agent_app_id -k $kid -K $private_key -i $refresh_token -a https://$auth0_domain/ -s read -p -J -u refresh_token | jq -r .access_token)

```

Sample structure of SAML issued ID-JAG:

```json
{
  "jti": "IDAAG.jrdCpdgazbi52j3UxXT_MqgAUMW2n57EZq8RG0ucRnU",
  "iss": "https://integrator-4598441.okta.com",
  "aud": "https://amin.jp.auth0.com/",
  "iat": 1784620622,
  "exp": 1784620922,
  "sub": "00u14j584jskYLAVs698",
  "email": "test-xaa@example.com",
  "client_id": "Josz8cBBCWKA6Q7CkhyhYjbKY4hqjXMG",
  "sub_profile": "user",
  "scope": "read",
  "act": {
    "sub": "wlp15fk3702lJwVLG698",
    "sub_profile": "ai_agent"
  },
  "sub_id": {
    "format": "saml-nameid",
    "issuer": "http://www.okta.com/exk15fjrhugHeRpO1698",
    "nameid": "test-xaa@example.com",
    "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified"
  }
}
```

```shell
./token-exchange.sh -d $auth0_domain -c $client_id -x $client_secret -G jwt-bearer -s read -A $id_jag -r urn:todo0:api
```

# References
- [Auth0 Cross App Access (XAA)](https://auth0.com/docs/secure/call-apis-on-users-behalf/xaa)
- [Build Secure Agent-to-App Connections with Cross App Access (XAA)](https://developer.okta.com/blog/2025/09/03/cross-app-access#use-okta-to-secure-ai-applications-with-oauth-20-and-openid-connect-oidc)
- [auth0-cross-app-access-inspector](https://github.com/auth0-samples/auth0-cross-app-access-inspector)