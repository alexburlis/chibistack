# Third-party software

Chibistack's own code is covered by [LICENSE](LICENSE). Dependencies retain their
own licenses. The preview archive includes the `hostctl`, `hostmcp` and
`render-host` executables, source, and the HTTP example. It does not include
Tailscale, restic, Caddy, Fedora packages, or their container images.

## Included Go dependencies

The Linux AMD64 utilities are built with Go 1.27.3 and `CGO_ENABLED=0`. The
production package graph for `cmd/hostctl`, `cmd/hostmcp` and
`scripts/render-host.go` selects these nine third-party modules. Each linked
license below is copied from that exact module version, including its copyright
and disclaimer. Existing upstream `PATENTS` files are included alongside the
license. The module-cache source is not vendored into this preview.

| Module | Version | License material |
| --- | --- | --- |
| `github.com/modelcontextprotocol/go-sdk` | `v1.8.0` | [Complete upstream licensing transition text](licenses/mcp-go-sdk-v1.8.0/LICENSE): Apache-2.0 and retained MIT contributions; documentation excluding specifications is CC-BY-4.0. |
| `github.com/google/jsonschema-go` | `v0.4.3` | [MIT](licenses/jsonschema-go-v0.4.3/LICENSE) |
| `github.com/segmentio/asm` | `v1.1.3` | [MIT](licenses/segmentio-asm-v1.1.3/LICENSE) |
| `github.com/segmentio/encoding` | `v0.5.4` | [MIT](licenses/segmentio-encoding-v0.5.4/LICENSE) |
| `github.com/yosida95/uritemplate/v3` | `v3.0.2` | [BSD-3-Clause](licenses/uritemplate-v3.0.2/LICENSE) |
| `golang.org/x/oauth2` | `v0.35.0` | [BSD-3-Clause](licenses/x-oauth2-v0.35.0/LICENSE) |
| `golang.org/x/sync` | `v0.20.0` | [BSD-3-Clause](licenses/x-sync-v0.20.0/LICENSE), [PATENTS](licenses/x-sync-v0.20.0/PATENTS) |
| `golang.org/x/sys` | `v0.41.0` | [BSD-3-Clause](licenses/x-sys-v0.41.0/LICENSE), [PATENTS](licenses/x-sys-v0.41.0/PATENTS) |
| `golang.org/x/time` | `v0.15.0` | [BSD-3-Clause](licenses/x-time-v0.15.0/LICENSE), [PATENTS](licenses/x-time-v0.15.0/PATENTS) |

The additional entries in `go.sum` do not by themselves establish inclusion in a
binary. In this build, `github.com/golang-jwt/jwt/v5`, `github.com/google/go-cmp`
and `golang.org/x/tools` are outside the production utility package graph.

## Go runtime and standard library

The [Go license](licenses/go1.27.3/LICENSE) and
[patent grant](licenses/go1.27.3/PATENTS) apply to the Go runtime and standard
library. The notice directory also includes the licenses and patent grants for
the standard library's vendored `golang.org/x/crypto`, `x/net`, `x/sys` and
`x/text` code. These copies are from the compiler's source tree, independently
of similarly named modules above.

[Additional notices](licenses/go1.27.3/EXTRA_NOTICES.txt) preserve the selected
source files' fiat-crypto, Sun Microsystems, Stephen L. Moshier/Cephes,
Lucent Technologies/Vita Nuova, Rijndael and SLEEF notices. The set conservatively
covers selected package sources before linker dead-code elimination.
[NOTICE_SOURCES.json](licenses/go1.27.3/NOTICE_SOURCES.json) records the source
paths and hashes. [UPSTREAM_VERIFICATION.json](licenses/go1.27.3/UPSTREAM_VERIFICATION.json)
records byte matches against the official Go source and verifies that these
notice sources are unchanged between Go 1.27.3 and Go 1.27.4.

The HTTP example uses only the Go standard library. Its image is built with Go
1.27.4 and `CGO_ENABLED=0`; the same Go notice texts cover its selected sources.
[HTTP_EXAMPLE_COVERAGE.json](licenses/go1.27.3/HTTP_EXAMPLE_COVERAGE.json) records
that coverage. Preserve the example's own MIT license and the complete Go notice
directory with its binary or container image.

## Tools fetched by the operator

`scripts/assemble-preview-utilities` downloads checksum-pinned upstream Linux
AMD64 releases of Tailscale 1.102.5 and restic 0.19.1 on the operator's machine.
The quickstart separately selects Caddy 2.11.9-alpine by its published Linux
AMD64 OCI digest. These are
external installation inputs, not executables distributed in the preview archive.

| Tool | Upstream source and rights |
| --- | --- |
| Tailscale `1.102.5` | [Versioned source](https://github.com/tailscale/tailscale/tree/v1.102.5), [BSD-3-Clause license](https://github.com/tailscale/tailscale/blob/v1.102.5/LICENSE). The Linux client also contains independently licensed dependencies. Preserve their notices when redistributing a binary; Tailscale's [license command](https://github.com/tailscale/tailscale/blob/v1.102.5/cmd/tailscale/cli/licenses.go) points to its platform license information. The software license does not grant endorsement or rights to the hosted coordination service. |
| restic `0.19.1` | [Versioned source](https://github.com/restic/restic/tree/v0.19.1), [BSD-2-Clause license](https://github.com/restic/restic/blob/v0.19.1/LICENSE). Its dependencies have separate obligations. For example, the [blob cache](https://github.com/restic/restic/blob/v0.19.1/internal/bloblru/cache.go) uses `github.com/hashicorp/golang-lru/v2` `v2.0.7` under [MPL-2.0](https://github.com/hashicorp/golang-lru/blob/v2.0.7/LICENSE), which requires source availability and recipient instructions when the covered component is distributed in executable form. |
| Caddy `2.11.9-alpine` | [Versioned source](https://github.com/caddyserver/caddy/tree/v2.11.9), [Apache-2.0 license](https://github.com/caddyserver/caddy/blob/v2.11.9/LICENSE), [official image metadata](https://hub.docker.com/v2/namespaces/library/repositories/caddy/tags/2.11.9-alpine). The separately pulled image has its own dependency and license inventory. The custom `infra/proxy/Containerfile` is a separate build recipe and does not establish the contents of the quickstart's stock image. |

This notice set covers the included Chibistack binaries and HTTP example. It is
not a complete redistribution bundle for the downloaded tools or external
images. Before distributing an assembled `utilities.tar` or a rebuilt proxy
image, include its exact third-party licenses and notices, satisfy any applicable
source-availability requirements, and identify the versions actually shipped.
Keep copyright notices, license conditions and disclaimers with every distributed
copy. Third-party names identify their origin; they do not imply endorsement.
