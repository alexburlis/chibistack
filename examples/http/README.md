# Run the HTTP example on Chibistack

Copy this directory's contents, including `.github` and `.containerignore`, to the
root of an application repository. The example serves an embedded page on port
8080 and returns `200 ready` at `/ready`. The image runs as UID 65532, needs no
mounts, and supports a read-only root filesystem. `/app/test` checks the same
handlers offline without a listener or filesystem writes.

The commands below prepare local files. Creating GitHub environments, uploading
secrets, DNS changes, host installation, and pushing `http-release` are separate
operator actions that can deploy production code. Obtain authority for those
effects first. GitHub runner and registry usage can incur provider charges.

## Check the example locally

Run these commands from the copied application directory:

```sh
go test ./...
go vet ./...
go run . --self-test
podman build --platform=linux/amd64 --file Containerfile --tag localhost/http-example .
podman run --rm --network=none --read-only --cap-drop=all \
	--security-opt=no-new-privileges --memory=64m --pids-limit=128 \
	--entrypoint /app/test localhost/http-example
```

The last command prints `HTTP handler checks passed` and exits zero. Building
requires access to the pinned Go image. Running `/app/test` requires no network.
For a local server check, run `go run .` and request
`http://127.0.0.1:8080/ready` from another terminal. Stop the server with Ctrl-C.

## Prepare the manifest

1. Edit `chibistack.json`. Set `app`, `user` to `app-APP`, the repository,
   lowercase GHCR image path, hostname, UID, and both backend ports.
   The example's UID 2001 and ports 18081/18082 suit an empty host only.
   Select unused values when adding an app to an existing host.
2. Keep `container_uid` at 65532, `container_port` at 8080, and
   `readiness_path` at `/ready`. Keep the branch, environment, and workflow path
   in agreement with the workflow. The workflow expects GitHub's
   `github-actions[bot]` creator ID 41898282 through the built-in `GITHUB_TOKEN`.
   A personal access token is not interchangeable with that token.
3. Install the base64 encoding of the raw 32-byte Ed25519 public key as
   `github.signing_public_key`. Keep the corresponding PEM private key outside
   this repository. The workflow consumes that PEM only as the protected
   environment secret `MINIMAL_HOST_SIGNING_KEY`.
4. Compute the hash of the final workflow bytes and insert that value as
   `github.workflow_sha256`:

   ```sh
   shasum -a 256 .github/workflows/chibistack-release.yml
   ```

5. Compute `shasum -a 256 chibistack.json` after all manifest edits.
   The exact bytes are the installed host policy and `HOST_CONFIG_SHA256` value.
   Reformatting the manifest changes this hash.

## Configure release admission

1. Create the GitHub environment `chibistack-production` for this repository.
   Permit only the `http-release` branch. Keep the signing key in this environment,
   never in a repository secret available to other workflows. Control writes to
   the release branch and changes to this workflow.
2. Set these environment variables and the environment secret:

   | Name | Value |
   |---|---|
   | `HOST_APP` | The manifest's `app`. |
   | `HOST_IMAGE` | The manifest's `image_repo`, such as `ghcr.io/owner/http-example`. |
   | `HOST_CONFIG_SHA256` | The SHA-256 of the exact installed manifest bytes. |
   | `MINIMAL_HOST_SIGNING_KEY` | Secret containing the Ed25519 PEM private key. |

3. Complete the host's app enrollment and DNS setup using Chibistack's operator
   runbook. Install the reviewed manifest before the first release. Grant the
   host read access to this repository and pull access to its image. No host or
   registry credential belongs in the application image.
4. Commit the application and create `http-release` at the approved commit.
   Push that branch only when deployment is authorized. Watch the release run
   finish successfully, then check the host deployment status and HTTPS `/ready`.

The workflow accepts pushes only, rejects reruns, checks the manifest and workflow
hashes, builds a Linux amd64 image, and runs `/app/test` under runtime restrictions.
Trivy rejects HIGH or CRITICAL vulnerabilities. A scanner download, database,
or scan failure stops publication. The workflow then pushes the image and signs a
GitHub deployment request containing its registry digest, source commit, run ID,
run attempt, repository, workflow path, application, and configuration hash.

The host admits the request only after the workflow completes successfully.
The host also checks the trusted creator, environment, exact branch head,
workflow bytes, signature, and source ancestry against the installed policy.
Do not rerun a release job. Push a new descendant commit to create a new run.
Changing workflow bytes or the signing policy requires the runbook's host policy
update before a new release can be admitted.

## Verify the pinned inputs

The workflow pins `actions/checkout` v7.0.1 to commit
`3d3c42e5aac5ba805825da76410c181273ba90b1`.
The [upstream tag API](https://api.github.com/repos/actions/checkout/git/ref/tags/v7.0.1)
provides that commit. The workflow verifies the Trivy v0.76.2 Linux amd64 archive
against SHA-256 `bc0fc726e017b8927a62b2d3531d7a84ee01769daf5c99ed866dced54089fdbf`
from the [upstream checksums](https://github.com/aquasecurity/trivy/releases/download/v0.76.2/trivy_0.76.2_checksums.txt).

The builder is the official Go 1.27.4 image, pinned to its multi-platform index
`sha256:205c7636d74e0ffbe3d007162df7d74f859f5a8c8322dfb9f907977686c126cf`.
Inspect that immutable reference with `docker buildx imagetools inspect`.
The [builder source](https://github.com/docker-library/golang/blob/6aa5c5f09346fb65fdefa941a23eb3cb25ba7b1a/1.27/trixie/Dockerfile)
checks the Go archive hash. Only the compiled binary and Go license notices enter
the scratch runtime image. The `licenses` directory adds the Go standard library
notices, vendored dependency license texts, and the Chibistack license under
`/licenses`. The example uses the Go standard library and has no
module downloads. The hosted runner supplies Podman, OpenSSL, jq, curl, and gh.
Their versions and the vulnerability database are not frozen by the workflow hash.
