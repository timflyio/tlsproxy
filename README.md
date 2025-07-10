# TlsProxy

TlsProxy is a TLS server listening on `::1` on `PORT` (default 443).
It accepts connections, auto-generating TLS certificates based on the SNI, and proxying
the request through an HTTP proxy specified in the `PROXY` environment variable,
defaulting to `http://tokenizer.flycast`.

It rejects connections except for targets specified in the TARGETS environment variable,
which defines a list of host names and a name of an environment variable with proxy
authentication to use when proxying for that target. This is an example:

```
TARGETS=api.anthropic.com=ANTHROPIC_API_KEY,api.openai.com=OPENAI_API_KEY,api.github.com=GH_TOKEN
```

When using the fly tokenizer, these auth environment variables would be set to a wrapped
secret that contains information on how the tokenizer will inject the secret in HTTP request headers.

This allows intercepting requests by setting DNS or `/etc/hosts` to direct a host to `::1`, for example by
`echo "::1 api.github.com" >> /etc/hosts`.

# Sealing keys

The `seal.go` program is a helper for sealing secrets for the tokenizer. It requires the sealing key
in the `SEAL_KEY` environment.  It seals keys for use with a specific target URL, and restricts access
for a single fly org and app. Here's an example for wrapping a bearer auth token for APP and ORG, which will
be filled in as `Authorization: Bearer TOKEN`:

```
  go run seal.go -org ORG -app APP -host api.host.com TOKEN
```

Here is an example of wrapping a token for the `x-api-auth` header, which will be filled in as
`x-api-auth: TOKEN`:

```
  go run seal.go -org ORG -app APP -host api.host.com -header x-api-auth TOKEN
```

See [tokenizer docs](https://github.com/superfly/tokenizer) for more details on sealing keys.

# Example usage

See [proxy pilot](https://github.com/timflyio/proxypilot) for an example that uses tlsproxy as a sidecar
so that the shell container does not have access to the real github token but can still use the `gh` client
to make github API requests.
