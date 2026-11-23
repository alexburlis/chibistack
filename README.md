# Chibistack

Deploy signed HTTP services to one Fedora 44 AMD64 host. Chibistack runs each app under its own rootless Podman identity, uses Caddy for HTTPS, and pulls releases from GitHub. The `v0.1` preview covers HTTP services. Plan for downtime during host reboots and app enrollment.

## 1. Prepare the example

Use a fresh Fedora 44 AMD64 machine with SELinux enforcing, cgroups v2, and independent console access. Use a domain you control if you want public HTTPS. The preview bundle contains `hostctl`, `hostmcp`, `render-host`, installer sources, and the complete [HTTP example](examples/http/README.md).

Download the Linux AMD64 bundle and `SHA256SUMS` from the [preview release](https://github.com/alexburlis/chibistack/releases/tag/v0.1.0-preview.2) into the same directory on the Fedora host. Run the following commands from that directory as root.

```sh
archive=chibistack-v0.1.0-preview.2-linux-amd64.tar.gz
checksum=$(awk -v archive="$archive" '$2 == archive' SHA256SUMS) &&
	test -n "$checksum" &&
	printf '%s\n' "$checksum" | sha256sum -c - &&
	tar --no-same-owner -xzf "$archive" -C /root &&
	cd "/root/${archive%.tar.gz}" &&
	sha256sum -c BINARY-SHA256SUMS &&
	cat VERSION SOURCE_COMMIT
```

Copy `examples/http/` into your app repository, including hidden files. Follow the [example’s release setup](examples/http/README.md) to fill in the manifest, pin the workflow hash, configure the release environment, and stage the `http-release` branch. Copy the reviewed `chibistack.json` to `/root/chibistack.json` on the Fedora host. Leave the branch unpushed until the host is ready to pull.

## 2. Install and start the host

Run the following as root. Supply a reviewed literal resolver IP for the host and apps. The utility script fetches checksum-pinned stock Tailscale and restic from their upstream release channels and assembles the installer’s five-file tar. Fedora supplies the remaining packages. Caddy comes from its public image registry by digest.

```sh
cd /root/chibistack-v0.1.0-preview.2-linux-amd64
dnf5 install -y bzip2 curl
./bin/hostctl config-check /root/chibistack.json
./scripts/assemble-preview-utilities /root/chibistack-utilities
proxy='docker.io/library/caddy@sha256:fc9cbc100585871d18d4e451cca7021785c90a7006087427ae5ceb3e4efe6424'
read -r -p 'Reviewed resolver IP: ' resolver
./bin/render-host --source "$PWD" --apps /root/chibistack.json \
  --proxy-image "$proxy" --dns-resolvers "$resolver" --out /root/chibistack-stage
read -r utility_hash _ < /root/chibistack-utilities/utilities.sha512
./scripts/install-fedora.sh /root/chibistack-stage /root/chibistack-utilities/utilities.tar "$utility_hash"
systemctl start minimal-host-helper.socket minimal-host-reconcile.service
```

The installer stages the host firewall without activating it. With console recovery available, review the generated `/etc/minimal-host/firewall.nft` against any other firewall and the provider’s ingress rules. The generated policy allows public HTTP and HTTPS, keeps the backends on loopback, and limits host SSH to Tailscale. Activate with `systemctl enable --now minimal-host-firewall.service` after verifying your recovery route. Preserve provider console access for the entire preview. Point the domain at the host and permit public TCP 80 and 443 once the policy is active.

Install a dedicated read-only GitHub token with Actions, Contents, and Deployments read access to the app repository. Install its root-owned input as `/etc/minimal-host/secrets/github-token` with `install -m 0600`. Keep the token out of the manifest.

For a private GHCR package, use the registry’s separate pull credential. Run `podman login ghcr.io` as the enrolled app user. Use `--password-stdin` with a protected input and persist the result with `--authfile /var/home/app-http-example/.config/containers/auth.json`. The file and its parent directory must be private to the app user. Grant that credential read access to the image when the first workflow creates the package.

Enable the poll timer after syncing `HOST_CONFIG_SHA256` with the installed manifest.

```sh
systemctl enable --now minimal-host-poll.timer
# Push http-release from the app checkout and wait for the workflow to succeed.
systemctl start minimal-host-poll.service
hostctl doctor http-example
```

Visit `https://YOUR_DOMAIN/ready`. `hostctl doctor http-example` checks the local proxy route and the accepted app’s readiness. Use `journalctl -u minimal-host-poll.service` if admission fails. The poller accepts successful first-attempt push runs for the current release branch head only.

## 3. Update policy, recover, and roll back

Update the workflow pin or signing policy by preparing a reviewed copy under `/root`. Preserve the original runtime fields. Run `hostctl config-check` and `hostctl update-release-policy` on the new file. Set `HOST_CONFIG_SHA256` to the new hash before pushing the reviewed workflow. Previously accepted releases remain available across policy-only changes. Keep the root-owned `.manifest` archives with the release receipts. Runtime edits such as ports, mounts, identity, or image repository require a separately planned maintenance procedure.

For a recovery drill, publish two reviewed releases of the example, reboot the disposable host, and check `hostctl doctor http-example`. With a second fixture app enrolled on the fresh host, give that app an invalid manifest before reboot. Check the reconciliation journal for the named failure, then check the healthy app’s readiness. Keep the original manifest bytes so you can restore the fixture. Run this drill on a disposable host.

Run rollback and check the resulting receipt as root:

```sh
printf '%s\n' '{"op":"rollback","app":"http-example"}' | hostctl helper
printf '%s\n' '{"op":"deployment_status","app":"http-example"}' | hostctl helper
hostctl doctor http-example
```

Rollback holds admission. Review the active release and its `high_water`, then use `hostctl resume http-example HIGH_WATER` to resume with a workflow run newer than that barrier. A host reboot interrupts traffic on a single server.

## Enroll another app

Prepare one manifest per app before the first install when possible. Set unique app identities, hostnames, and backend ports. Adding an app to an installed host is administrator maintenance with a planned interruption for existing apps. The fresh-host installer rejects changed or active installations. Plan a maintenance window, preserve state and config, review the rendered delta, and verify the existing routes and admission holds before resuming. The preview quickstart covers first install and policy-only changes.
