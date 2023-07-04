Contribution Guide
==================




## Best practices

1. Keep the image size as small as possible:
    - Do not produce redundant layers in the final image.
    - Cleanup temporary files and caches in the same layer were they were produced.
    - Remove unnecessary man pages, examples and documentation.

2. Build each project in its separate stage:
    - Do use layers granularly in non-final stages for better caching of build results.
    - Prepare all the final files as much as possible in their build stage before adding them to the final stage.




## CI workflow

At the moment `coturn/coturn` Docker image's [workflow is automated][1] via [GitHub Actions] in the following manner:

- On each push the image is built and tested.  
  This helps to track image regressions due to changes in the codebase.

- Image is built and tested automatically from `master` branch on weekly basis.  
  This helps to track image regressions due to changes in parent OS images (`debian`, `alpine`), their system packages, and other dependencies.

- On each push to `master` branch the image is published with `edge-debian` and `edge-alpine` tags.  
  This helps to test and try the latest `master` branch and its changes for whoever needs this.

- On each `docker/X.Y.Z-rN` tag creation the image is built using the `X.Y.Z` Coturn version (not the local sources), tested, and is published with all the version tags declared in [`Makefile`] (see `ALL_IMAGES`).  
  An appropriate [GitHub Release] for the `docker/X.Y.Z-rN` Git tag is also created automatically.

- Whenever the image is published, its description on container registries is automatically updated with its [README] file.




## Releasing

To produce a new release (version tag) of `coturn/coturn` Docker image, perform the following steps:

1. Upgrade the image version correctly in [`Makefile`] by bumping up either the `COTURN_VER` (if Coturn has changed it version) or the `BUILD_REV` (if anything else in the image has been changed). If the `COTURN_VER` has changed, the `BUILD_REV` may be reset to `0` (DO NOT reset when `ALPINE_VER`/`DEBIAN_VER` changes).

2. Complete an existing [CHANGELOG] or fill up a new one for the new version declared in [`Makefile`].

3. Update [README] with the new version declared in [`Makefile`].

4. Perform a `make release` command inside the `docker/coturn/` directory.




[CHANGELOG]: https://github.com/coturn/coturn/blob/master/docker/coturn/CHANGELOG.md
[GitHub Actions]: https://docs.github.com/actions
[GitHub Release]: https://github.com/coturn/coturn/releases
[README]: https://github.com/coturn/coturn/blob/master/docker/coturn/README.md

[`Makefile`]: https://github.com/coturn/coturn/blob/master/docker/coturn/Makefile

[1]: https://github.com/coturn/coturn/blob/master/.github/workflows/docker.yml
