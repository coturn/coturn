# Restore build support for (deprecated) OpenSSL 1.1.1

This folder vendors an **out-of-tree patch** that brings back the ability to
build coturn against **OpenSSL 1.1.1**. It is *not* applied to the coturn
sources — it is provided for downstream packagers and operators who are forced
to link against OpenSSL 1.1.1 and need a one-command way to restore that build.

> [!WARNING]
> **OpenSSL 1.1.1 is deprecated and end-of-life** (upstream EOL: 11 September
> 2023; no further public security fixes). coturn targets OpenSSL 3.x, and this
> patch exists only as a compatibility bridge for environments that cannot yet
> move off 1.1.1. Use it at your own risk and migrate to OpenSSL 3.x as soon as
> your platform allows.

## What it does

Commit `4c674289` ("OpenSSL: migrate to modern API for DH param", #1809) moved
the DH-parameter handling in `src/apps/relay/mainrelay.c` to the OpenSSL 3.x
`EVP_PKEY` / `OSSL_PARAM` API, which does not exist in OpenSSL 1.1.1. As a
result, current coturn no longer compiles against 1.1.1.

The patch conditionalizes those changes behind
`OPENSSL_VERSION_NUMBER >= 0x30000000L`, keeping the modern path for OpenSSL 3.x
while restoring the legacy `get_dh*()` / `DH_*` implementation for
OpenSSL >= 1.1.1. It touches only `src/apps/relay/mainrelay.c` and
`src/apps/relay/mainrelay.h`.

## Why it is needed

On AlmaLinux / RHEL / Rocky Linux 8, OpenSSL 3.5 is available in EPEL 8 but
cannot be used in practice: the other libraries coturn links against
(`libevent_openssl`, `libmariadb`, `libpq`) ship in RHEL 8 built and linked
against the system OpenSSL 1.1.1. Mixing two OpenSSL major versions in one
process is not viable, so coturn must also build against 1.1.1 on those
distributions.

## Source

- Upstream pull request: <https://github.com/coturn/coturn/pull/1817>
  ("Restore support for OpenSSL >= 1.1.1 (for AlmaLinux/RHEL/Rocky Linux 8)")
- Author: Robert Scheck
- Upstream commit: `c1110e6816c9c76668e6986efd282b9f57ef4fde`

## How to apply

From the repository root, choose one of:

```bash
# Preserve the original authorship as a real commit:
git am patches/openssl-1.1.1/0001-restore-openssl-1.1.1-support.patch

# Or apply to the working tree without committing:
git apply patches/openssl-1.1.1/0001-restore-openssl-1.1.1-support.patch

# Or with plain patch(1):
patch -p1 < patches/openssl-1.1.1/0001-restore-openssl-1.1.1-support.patch
```

Then configure and build as usual; the legacy code path is selected
automatically when it detects an OpenSSL version older than 3.0.

## Verification

The patch applies cleanly with `git apply --check` against the `master` commit
it was vendored at (`e2735cf0`). If a later change to `mainrelay.c` causes it to
no longer apply, regenerate it from the upstream pull request above.
