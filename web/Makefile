.DEFAULT_GOAL := server

PORT       ?= 1980
TOKEN_FILE ?= .tunnel-token

-include .env

.PHONY: server tunnel

server:
	./server.sh -p $(PORT)

tunnel:
	@test -n "$(TUNNEL_ID)" || { echo "TUNNEL_ID not set -- add it to .env" >&2; exit 1; }
	@echo "Tunnelling https://$(TUNNEL_HOSTNAME) -> http://localhost:$(PORT)"
	cloudflared tunnel run --url http://localhost:$(PORT) --token-file $(TOKEN_FILE) $(TUNNEL_ID)
