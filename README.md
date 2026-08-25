# AWS RFC 9421 authorizer for containerd

This repository is an experimental node-local request authorizer for the
[`containerd-request-authorizer-prototype`](https://github.com/yyichenn/containerd-request-authorizer-prototype).
It retrieves temporary AWS credentials, signs RFC 9421 signature bases, and
serves the result to containerd over a protected Unix socket.

The prototype replaces a reusable registry token on the request path with a
request-bound HTTP Message Signature. It does not change AWS authorization:
the registry still resolves the IAM principal and applies current policies.

This code is a feasibility prototype, not a production credential daemon or a
stable plugin API.

## Build

```bash
go build -o bin/containerd-aws-rfc9421-authorizer \
  ./cmd/containerd-aws-rfc9421-authorizer
```

## Run

```bash
bin/containerd-aws-rfc9421-authorizer \
  --region us-east-1 \
  --socket /run/containerd/aws-rfc9421-authorizer.sock
```

The process uses the AWS SDK default credential chain. On an EC2 node, that
normally resolves the node role through IMDS unless an earlier credential
source is configured. Environment credentials, shared profiles,
`credential_process`, web identity, and container credential endpoints are
also supported by the SDK.

The signer intentionally requires temporary credentials with a session token.
The secret access key and derived signing key stay in this process. Containerd
receives the access key ID, session token, credential scope, and signature.

Use `--credential-context <handle>` to require an exact opaque handle from the
containerd CRI request. This prototype maps one handle to the daemon's current
AWS credential source. A production design would define identity resolution
and authorization for multiple handles.

## Containerd configuration

Node-wide host selection:

```bash
CONTAINERD_REGISTRY_RFC9421_HOSTS=123456789012.dkr.ecr.us-east-1.amazonaws.com
CONTAINERD_REGISTRY_RFC9421_SIGNER_SOCKET=/run/containerd/aws-rfc9421-authorizer.sock
```

Experimental per-pull selection:

```toml
[proxy_plugins."aws-rfc9421"]
  type = "request-authorizer"
  address = "/run/containerd/aws-rfc9421-authorizer.sock"
```

## Protocol

Containerd calls two JSON endpoints over the Unix socket:

- `POST /v1/signing-context` retrieves public credential metadata and a
  single-use context ID.
- `POST /v1/sign` sends an RFC 9421 signature base and consumes that context
  ID.

The signer derives an HMAC key using the AWS4 date, region, service, and
`aws4_request` scope. Containerd formats the request headers according to RFC
9421. This is an RFC 9421 profile using AWS4 key derivation; it is not the
SigV4 wire protocol.

The socket grants signing authority. It must be owned by the authorizer and
containerd identities and unavailable to untrusted workloads. The command
creates the socket with mode `0600`.

## Current scope

- Temporary AWS credentials only.
- ECR service scope.
- One credential source per daemon.
- Five-minute, single-use signer context IDs.
- No process supervision or credential-context policy engine.
- No compatibility commitment for the Unix-socket protocol.
