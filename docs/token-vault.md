# Refresh Token Exchange with Token Vault
```shell
./resource-owner.sh -d domain -c clientId -x clientSecret -u user -p pass -s openid,offline_access -m

export refresh_token='$refresh_token'

./token-exchange.sh -d domain -c clientId -x clientSecret -f ConnectionName -R -i "${refresh_token}"
```


# Access Token Exchange with Token Vault
```shell
./resource-owner.sh -d domain -c publicClientId -u user -p pass -a some.api

export access_token='$access_token'

./token-exchange.sh -d domain -c apiClientId -x apiClientSecret -f ConnectionName -A -i "${access_token}" -a some.api
```