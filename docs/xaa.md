# Setup

Follow Auth0 XAA setup guide [here](https://auth0.com/docs/secure/call-apis-on-users-behalf/xaa).

# Testing

## Step 1 - Get id_token from Requesting App (agent0)

```bash
export okta_domain='amin.oktapreview.com'
export req_app_id='0oazekni6zXya9mh91d7'    # Agent0 in Okta

./authorize.sh -d $okta_domain -c $req_app_id -u http://localhost:3000/login/callback -C

export id_token='....'
```

### Step 2 - Request ID-JAG using id_token

```bash
export auth0_domain='abbaspour.auth0.com'
export req_app_secret='ZFoR7xxxx-IRTc9cD'   # Agent0 in Okta

export id_jag=`./token-exchange.sh -d $okta_domain -c $req_app_id -x $req_app_secret \
  -i $id_token -a https://$auth0_domain/ -r urn:todo0:api -p -J | jq -r .access_token`
```

Here is a sample full payload of an exchange result 
```json  
{
  "token_type":"N_A",
  "expires_in":300,
  "access_token":"eyJraWQ....10zjUw",
  "issued_token_type":"urn:ietf:params:oauth:token-type:id-jag"
}
```  

And here is a sample decoded ID-JAG JWT

```json
{
  "jti": "IDAAG.agk1Ey5Rx64q18AF4uL0z5b-7ij-eV6JLlVYMSpf-yo",
  "iss": "https://amin.oktapreview.com",
  "aud": "https://abbaspour.auth0.com/",
  "iat": 1780371959,
  "exp": 1780372259,
  "sub": "00uzekrk6tGSxXmRh1d7",
  "resource": "urn:todo0:api",
  "email": "bob@tables.fake",
  "client_id": "vlbB747IIDdNvkEqiNgUq5JNmIhH8bob"
}
```

### Step 3 - Request access_token using ID-JAG

```bash
export client_id='vlbB747IIDdNvkEqiNgUq5JNmIhH8bob'   # Agent0 in Auth0
export client_secret='PaAvicxxxxxJbxkMj4'             # Agent0 in Auth0

./token-exchange.sh -d $auth0_domain -c $client_id -x $client_secret -G jwt-bearer -s s1 -A $id_jag
```