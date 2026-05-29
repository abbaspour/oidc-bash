# Setup

Follow Auth0 XAA setup guide [here](https://auth0.com/docs/secure/call-apis-on-users-behalf/xaa).

# Testing

## Step 1 - Get id_token from Requesting App (agent0)

```bash
export okta_domain='amin.oktapreview.com'
export req_app_id='0oaz5x0wy2Ciyc6AE1d7'    # Agent0

./authorize.sh -d $okta_domain -c $req_app_id -C

export id_token='....'
```

### Step 2 - Request ID-JAG using id_token

```bash
export req_app_secret='ZFoR7xxxx-IRTc9cD'              # Agent0
export auth0_domain='abbaspour.auth0.com'

./token-exchange.sh -d $okta_domain -c $req_app_id -x $req_app_secret \
  -i $id_token -a https://$auth0_domain/ -r urn:todo0:api -p -J     
```

