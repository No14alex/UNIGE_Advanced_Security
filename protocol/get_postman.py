from pathlib import Path
import json
import handshake, rest_client_demo


# this creates demo data for interaction between alice and bob 
token = "demo-token"

alice = handshake.create_identity("alice")
bob = handshake.create_identity("bob")

data = {
    "alice": {
        "headers": rest_client_demo.auth_headers(alice, token),
        "bundle": rest_client_demo.bundle_json(alice),
    },
    "bob": {
        "headers": rest_client_demo.auth_headers(bob, token),
        "bundle": rest_client_demo.bundle_json(bob),
    },
}

Path("postman_demo_data.json").write_text(json.dumps(data, indent=2))
print("Wrote postman_demo_data.json")
