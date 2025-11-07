```shell
./authorize.sh -d auth0.domain -c Ro1XUdliEm2l2xsX2mxO1L92Cg8h6ng7 -x xxxxx -B "I am an Agent" -H 'auth0|690d2c5ffdb9b40c92fc2498'
export auth_req_id=xxxx

./exchange.sh -d auth0.domain  -c Ro1XUdliEm2l2xsX2mxO1L92Cg8h6ng7 -x xxxx -r "${auth_req_id}"
```