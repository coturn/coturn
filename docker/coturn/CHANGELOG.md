Coturn TURN server Docker image changelog
=========================================




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
