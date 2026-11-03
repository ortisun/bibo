# factory-testkit

- Status: written on 2026-11-03. It covers one thing only: the container image that one test of this crate needs. The rest of the crate is documented in its source and in the architecture decision records that name it ([ADR 0002](../../docs/adr/0002-workspace-layout-and-dependency-rule.md), [ADR 0015](../../docs/adr/0015-composition-library.md)).
- Form: reference.
- Goal: say which image the hostile-repository test runs git in, where it came from, and how to move to another one.

## The image of the hostile-repository test

The test `fx::repos::tests::hostile_git_configuration_runs_code_when_unhardened_and_nothing_when_hardened` is the only test that runs content of a hostile repository. It runs git inside a container with the hardened profile (no network, a read-only root, no capabilities, no new privileges, limits on processes and memory) and shows two things: the same repository runs code on the host when git is not hardened, and runs nothing when git is hardened as `docs/security/sandbox-policy.md` section 6.2 says.

| Item | Value |
|---|---|
| Image | `alpine/git`, a public image on Docker Hub |
| Default the test uses | `alpine/git@sha256:ac6c828f15d82775d204d3d75112e1d34af8945da80ccf922713c9891ba68e7a` |
| Pulled | 2026-11-03, once, with `docker pull alpine/git:latest` |
| Image created | 2026-11-01 at 07:59 (-03:00), 146 MB, the digest above is that of its manifest list |
| Why a digest | A tag moves. `latest` read on another day is another image, and a test of hostile git should not run whatever the machine happens to hold. |

The test never pulls. It asks the Docker daemon for the image by that digest and, if the machine does not hold it, the test ends BLOCKED with a line that says so. It is never counted as passed. To make the test run on a machine that does not have the image, pull it by digest:

```bash no-run reason="it downloads an image from Docker Hub"
docker pull alpine/git@sha256:ac6c828f15d82775d204d3d75112e1d34af8945da80ccf922713c9891ba68e7a
```

`FACTORY_TEST_GIT_IMAGE` replaces the default for a machine that holds another image with git in it. The test then runs on whatever that image is, and the digest above no longer applies.

## Moving to a newer git

1. Pull the new image once and read its digest with `docker images --digests alpine/git`.
2. Change `GIT_IMAGE_DIGEST` in `src/fx/repos/tests.rs`, and the digest and the dates in this file.
3. Run the test. It must pass with the new image before the change is merged.

Do not remove the old image from a machine with `docker image prune`: other projects on the same Docker daemon may use it. Remove only an image you pulled yourself and know nothing else uses.
