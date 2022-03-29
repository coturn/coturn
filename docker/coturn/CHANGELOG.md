Coturn TURN server Docker image changelog
=========================================




## [4.5.2-r10] · 2022-03-29
[4.5.2-r10]: /../../tree/docker/4.5.2-r10

### Security updated

- [Alpine Linux] 3.15.3: <https://github.com/docker-library/official-images/commit/e83c8d565978ce1edf1b7bb565484e8cb4419d24>
- [Debian] "bullseye" 20220328: <https://github.com/docker-library/official-images/commit/805cd38af6aec5e5a475c0229c6c1c9831af6124>




## [4.5.2-r9] · 2022-03-25
[4.5.2-r9]: /../../tree/docker/4.5.2-r9

### Security updated

- [Alpine Linux] 3.15.2: <https://github.com/docker-library/official-images/commit/72599f4196000032663a637e542cd23b4dc68936>
- [Debian] "bullseye" 20220316: <https://github.com/docker-library/official-images/commit/1e1bb99db26edc6b8605d83eefc22e1288203a20>




## [4.5.2-r8] · 2021-12-03
[4.5.2-r8]: /../../tree/docker/4.5.2-r8

### Added

- Default TLS ports. ([#860])

[#860]: /../../pull/860




## [4.5.2-r7] · 2021-11-25
[4.5.2-r7]: /../../tree/docker/4.5.2-r7

### Upgraded

- [Alpine Linux] 3.15: <https://alpinelinux.org/posts/Alpine-3.15.0-released.html>




## [4.5.2-r6] · 2021-11-15
[4.5.2-r6]: /../../tree/docker/4.5.2-r6

### Security updated

- [Alpine Linux] 3.14.3: <https://github.com/docker-library/official-images/commit/89298ea1c14b4241dcf3bad1b3092d178ca1ecbc>




## [4.5.2-r5] · 2021-08-29
[4.5.2-r5]: /../../tree/docker/4.5.2-r5

### Upgraded

- [Debian Linux] "bullseye": <https://www.debian.org/releases/bullseye/releasenotes>




## [4.5.2-r4] · 2021-08-28
[4.5.2-r4]: /../../tree/docker/4.5.2-r4

### Security updated

- [Alpine Linux] 3.14.2: <https://github.com/docker-library/official-images/commit/b54effe0cc65795f29752ecc197328a04326a6f2>




## [4.5.2-r3] · 2021-08-09
[4.5.2-r3]: /../../tree/docker/4.5.2-r3

### Security updated

- [Alpine Linux] 3.14.1: <https://github.com/docker-library/official-images/commit/a52e64df36ca65954c6c7f57ad242634e834c73a>




## [4.5.2-r2] · 2021-06-21
[4.5.2-r2]: /../../tree/docker/4.5.2-r2

### Upgraded

- [Alpine Linux] 3.14: <https://alpinelinux.org/posts/Alpine-3.14.0-released.html>




## [4.5.2-r1] · 2021-06-03
[4.5.2-r1]: /../../tree/docker/4.5.2-r1

### Added

- [Prometheus] support with [prometheus-client-c] 0.1.3: <https://github.com/digitalocean/prometheus-client-c/releases/tag/v0.1.3> ([#754])

### Improved

- Use DNS requests to discover external IP address in `detect-external-ip` script ([#753]).

### Fixed

- Incorrect linking with [mongo-c-driver] on [Debian Linux] image.

[#753]: /../../pull/753
[#754]: /../../pull/754




## [4.5.2-r0] · 2021-04-15
[4.5.2-r0]: /../../tree/docker/4.5.2-r0

### Created

- [Coturn] 4.5.2: <https://github.com/coturn/coturn/blob/upstream/4.5.2/ChangeLog> 
- [Alpine Linux] 3.13: <https://alpinelinux.org/posts/Alpine-3.13.0-released.html>
- [Debian Linux] "buster": <https://www.debian.org/releases/buster/releasenotes>
- [mongo-c-driver] 1.17.5 (`debian` only): <https://github.com/mongodb/mongo-c-driver/releases/tag/1.17.5>
- Supported platforms:
    - `linux/amd64`
    - `linux/arm64`
    - `linux/arm/v6`
    - `linux/arm/v7`
    - `linux/ppc64le`
    - `linux/s390x`





[Alpine Linux]: https://www.alpinelinux.org
[Coturn]: https://haraka.github.io
[Debian Linux]: https://www.debian.org
[mongo-c-driver]: https://github.com/mongodb/mongo-c-driver
[Prometheus]: https://prometheus.io
[prometheus-client-c]: https://github.com/digitalocean/prometheus-client-c
