# lokkju/r2-lfs

A fork of [ken109/r2-lfs](https://github.com/ken109/r2-lfs) with two additions for GitHub Actions
callers:

- `ACTIONS_OIDC_REFS`: comma-separated ref patterns (`*` matches any characters). When set, an
  Actions token whose `ref` claim is missing or matches none is refused.
- `ACTIONS_OIDC_ALLOWLIST=on`: an Actions token may download only the object ids listed in
  `_allowlist/{owner}/{repo}.txt` in the bucket, one lowercase 64-hex id per line. A missing or
  malformed list refuses every Actions download. Operator and other credentials are unaffected.

Branch `codexpublicus` carries these changes on top of an upstream release tag. `package.json`
keeps the upstream version so `scripts/upgrade-from-upstream.sh` keeps working; releases of this
fork are tagged `v<upstream>-cp.<n>`.
