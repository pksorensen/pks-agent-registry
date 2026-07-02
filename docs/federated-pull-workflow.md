# Federated pull from GitHub Actions (no secrets)

A customer's GitHub Actions workflow can authenticate against
`registry.agentics.dk` with its **GitHub OIDC token** instead of a stored
username/password — the same federated-credential model as Azure/AWS/GCP
(see [ADR 0003](adr/0003-github-oidc-federated-auth.md)).

## How it works

1. We create a **trust binding** for the customer's repo (optionally limited
   to one GitHub environment): `agent-registry federation add
   context-and/skills-marketplace --environment production --pull
   agentics/pks-agent-marketplace` — or via agentics.dk/admin/registry
   ("Federated access").
2. Their workflow requests a GitHub OIDC token with
   `audience=registry.agentics.dk` and uses it as the docker password. The
   GitHub token lives ~5 minutes and is consumed **once**: docker exchanges it
   at our `/token` endpoint for a registry-signed token (30 min) that covers
   the whole pull.
3. The pipeline mirrors the image into the customer's own registry (e.g. ACR),
   so their **runtime never depends on our infrastructure** — Azure Container
   Apps then pulls from their ACR with managed identity.

## Customer workflow

```yaml
name: mirror-marketplace-image

on:
  workflow_dispatch:

permissions:
  id-token: write # mint the GitHub OIDC token
  contents: read

jobs:
  mirror:
    runs-on: ubuntu-latest
    # If the trust binding is environment-scoped, the job must run in it:
    environment: production
    steps:
      - name: Log in to registry.agentics.dk (federated, no secrets)
        run: |
          JWT=$(curl -sSf -H "Authorization: Bearer $ACTIONS_ID_TOKEN_REQUEST_TOKEN" \
            "$ACTIONS_ID_TOKEN_REQUEST_URL&audience=registry.agentics.dk" | jq -r .value)
          echo "$JWT" | docker login registry.agentics.dk -u oauth2 --password-stdin

      - name: Log in to the customer ACR (their own OIDC federation)
        uses: azure/login@v2
        with:
          client-id: ${{ vars.AZURE_CLIENT_ID }}
          tenant-id: ${{ vars.AZURE_TENANT_ID }}
          subscription-id: ${{ vars.AZURE_SUBSCRIPTION_ID }}
      - run: az acr login --name <customeracr>

      - name: Mirror
        run: |
          docker pull registry.agentics.dk/agentics/pks-agent-marketplace:latest
          docker tag registry.agentics.dk/agentics/pks-agent-marketplace:latest \
            <customeracr>.azurecr.io/agentics/pks-agent-marketplace:latest
          docker push <customeracr>.azurecr.io/agentics/pks-agent-marketplace:latest
```

Notes:

- The `audience` **must** be exactly the registry hostname
  (`registry.agentics.dk`); tokens minted for another audience are rejected.
- Fetch the JWT in the same step as (or right before) `docker login` — it
  expires 5 minutes after minting. Our minted token then lasts 30 minutes.
- The username (`oauth2`) is ignored; identity comes from the validated token.
- Trust bindings pin the repository's immutable GitHub ID on first use, so
  repo renames keep working and name-squatting does not.

## Server-side requirements

- `REGISTRY_PUBLIC_URL=https://registry.agentics.dk` set on the registry
  (arms the token service; see [README](../README.md#environment-variables)).
- A trust binding for the repo (`federation add` CLI, `/_mgmt/federation`
  API, or the agentics.dk admin UI).
