# ADR 0005: Azure managed identity federation

## Status

Accepted.

## Context

Agentics Azure Sandbox installations need to mirror private product images into
their customer-owned ACR without storing a long-lived password. Their landing
zone already creates a stable user-assigned managed identity.

## Decision

The registry accepts Microsoft Entra managed-identity assertions as a third
federated credential type when `REGISTRY_AZURE_OIDC_AUDIENCE` is configured. An
administrator must first create an `azure` trust binding containing all three
immutable identifiers:

- tenant ID (`tid`);
- managed identity client ID (`appid` for v1 tokens, `azp` for v2 tokens);
- managed identity service-principal object ID (`oid`).

The registry validates the JWT signature against Microsoft's common signing
keys, validates its exact tenant-specific issuer and audience, and then requires
all three claims to match the binding. Azure access is pull-only unless the
binding explicitly grants an owner namespace and push permission.

The managed identity requests `api://AzureADTokenExchange`; Entra emits its
backing first-party application ID (`fb60f99c-7a34-4190-8149-302f77469936`) in
the signed `aud` claim, which is therefore the registry's default validation
audience. It is the standard audience for short-lived workload-federation
assertions and is available
to managed identities across tenants without provisioning a service principal
for a custom resource application in every customer tenant. The registry acts
as the relying token service: it never forwards the assertion to Azure and only
mints an OCI token after matching the explicitly approved immutable claims. A
private registry deployment may instead use its own Application ID URI.

The assertion is supplied as the Basic password with username `oauth2`, the
same convention used for GitHub workload tokens. The registry then returns its
normal short-lived OCI bearer token.

## Consequences

- Customer deployments can authenticate from Azure without retaining a
  registry password.
- Registering an identity grants nothing unless it can obtain a correctly
  scoped Entra token for the configured registry audience.
- The Agentics control plane can associate the binding with a customer
  installation and revoke future pulls by deleting it.
- The assertion is audience-bound to Entra workload federation and cannot be
  reused as an ARM, Foundry, or customer-resource access token.
