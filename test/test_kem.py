import oqs
'''
Test code :

Bob generates a pair of keys ML-KEM
Alice uses Bob's public key to encapsulate the secret 
Bob recuperated the secret with his private key

'''


def test_kem():

    ml_kem = "ML-KEM-512"
    print(f"Testing KEM with algorithm: {ml_kem}")

    try:
        # Create client and server instances
        with oqs.KeyEncapsulation(ml_kem) as client:
            with oqs.KeyEncapsulation(ml_kem) as server:

                print(f"\n  - Client: generating keypair...")
                public_key = client.generate_keypair()

                print(f" - Server: encapsulating secret using client's public key...")
                ciphertext, shared_secret_server = server.encap_secret(
                    public_key)
                print(
                    f"Server generated secret: {shared_secret_server.hex()[:32]}...")

                print(
                    f" - Client: decapsulating ciphertext to obtain the shared secret...")
                shared_secret_client = client.decap_secret(ciphertext)
                print(
                    f"Client obtained secret:  {shared_secret_client.hex()[:32]}...")

                # Verify that both parties have the same shared secret
                if shared_secret_client == shared_secret_server:
                    print(f"\n  Success! Shared secrets match.")
                else:
                    print(f"\nFailure! Shared secrets do not match.")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == "__main__":
    test_kem()
