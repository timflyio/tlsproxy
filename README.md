# TlsProxy

TlsProxy is a TLS server listening on `::1` on `PORT` (default 443).
It auto-generates certs based on SNI, and then proxies the request through `PROXY` to `URL`
with sealed `URLAUTH`.
By default this proxies through `http://tokenizer.fly.io` to `https://api.github.com`.

This allows intercepting requests by setting DNS or `/etc/hosts` to direct a host to `::1`, for example by
`echo "::1 api.github.com" >> /etc/hosts`.

See [tokenizer docs](https://github.com/superfly/tokenizer) for details on sealing keys.

See [proxy pilot](https://github.com/timflyio/proxypilot) for an example that uses tlsproxy as a sidecar
so that the shell container does not have access to the real github token but can still use the `gh` client
to make github API requests.

## Notes

Tlsproxy proxies through another proxy to a single target, but it could easily be made to proxy
to several targets based on the SNI and Host header field, with a different sealed secret for each
target.
