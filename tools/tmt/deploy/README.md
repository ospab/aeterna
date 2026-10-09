# Running tmt.ospab.org

The repository is static files; the Ed25519 *private* key never goes on the server.

## One-time server setup
1. DNS: A/AAAA record `tmt.ospab.org` -> your server.
2. `sudo mkdir -p /var/www/tmt.ospab.org/x86_64 && sudo chown $USER /var/www/tmt.ospab.org -R`
3. Copy `tmt.ospab.org.conf` to `/etc/nginx/sites-available/`, symlink into `sites-enabled/`, `sudo nginx -t && sudo systemctl reload nginx`.
4. `sudo certbot --nginx -d tmt.ospab.org`
5. Check: `curl -I https://tmt.ospab.org/x86_64/index` (after the first upload).

## Adding or updating a package (on your PC)
```
bash tools/tmt/build.sh                       # builds tools/tmt/bin/tmt
bash apps/build.sh                            # or your own build; writes apps/dist/*.tmt
# write a manifest (see apps/pkg/*.toml), then:
tools/tmt/bin/tmt pack my.toml -o repo-work/
tools/tmt/bin/tmt repo add  repo/ repo-work/*.tmt
tools/tmt/bin/tmt repo index repo/
tools/tmt/bin/tmt repo sign  repo/             # uses C:\Users\<you>\.ospab\tmt.key
tools/tmt/bin/tmt repo verify repo/            # sanity check against userland/tomato/repo_key.pub
rsync -av --delete repo/x86_64/ user@server:/var/www/tmt.ospab.org/x86_64/
```
Upload order matters little, but upload `index.sig` last (`rsync` the .tmt files first, then index, index.sig) so clients never see a new index without its packages.
Bump `version` in the manifest for every change: package files are cached as immutable.

## Key
`tmt keygen` made the key pair; the public key is compiled into the OS (`userland/tomato/repo_key.pub`). Back up `tmt.key`. If it is lost or leaked you must generate a new pair and ship a new kernel/ISO.

## Testing locally
`python -m http.server 8000 --bind 0.0.0.0 --directory repo`, then in the guest (QEMU user-net):
`echo repo=http://10.0.2.2:8000/x86_64/ > /etc/tomato.conf; tomato -Sy; tomato -S calc`.
`tools/tmt/e2e-qemu.ps1` automates this including tampered-index/package cases.
