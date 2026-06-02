## Reference
https://docs.developer.singpass.gov.sg/docs/technical-specifications/singpass-authentication-api

## Staging

### Authorize
```bash
./authorize.sh -d stg-id.singpass.gov.sg \
  -c OMaeWMfqhId0wwR4FGs7gGgCDCUYNqgW -T code \
  -u https://id.abbaspour.net/login/callback \
  -S s1 -s openid -f pkce -n n1 -U auth -C
```

### Exchange
```bash
./exchange.sh -d stg-id.singpass.gov.sg \
  -c OMaeWMfqhId0wwR4FGs7gGgCDCUYNqgW \
  -u https://id.abbaspour.net/login/callback \
  -k "sig-2021-08-30T04:38:19Z" \
  -K "Public-and-Private-Keypair.json" \
  -A ES256 \
  -U token \
  -t 100 \
  -p \
  -X VERIFIER \
  -a CODE
```