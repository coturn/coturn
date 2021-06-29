Coturn TURN server Docker image
===============================

[![Docker CI](https://github.com/coturn/coturn/actions/workflows/docker.yml/badge.svg  "Docker CI")](https://github.com/coturn/coturn/actions/workflows/docker.yml)
[![Docker Hub](https://img.shields.io/docker/pulls/coturn/coturn?label=Docker%20Hub%20pulls "Docker Hub pulls")](https://hub.docker.com/r/coturn/coturn)

[Docker Hub](https://hub.docker.com/r/coturn/coturn)
| [GitHub Container Registry](https://github.com/orgs/coturn/packages/container/package/coturn)
| [Quay.io](https://quay.io/repository/coturn/coturn)

[Changelog](https://github.com/coturn/coturn/blob/master/docker/coturn/CHANGELOG.md)




## Supported tags and respective `Dockerfile` links

- [`4.5.2-r2`, `4.5.2-r0-debian`, `4.5.2`, `4.5.2-debian`, `4.5`, `4.5-debian`, `4`, `4-debian`, `debian`, `latest`][d1]
- [`4.5.2-r2-alpine`, `4.5.2-alpine`, `4.5-alpine`, `4-alpine`, `alpine`][d2]




## Supported platforms

- `linux/amd64`
- `linux/arm64`
- `linux/arm/v6`
- `linux/arm/v7`
- `linux/ppc64le`
- `linux/s390x`




## What is Coturn TURN server?

The TURN Server is a VoIP media traffic NAT traversal server and gateway. It can be used as a general-purpose network traffic TURN server and gateway, too.

> [github.com/coturn/coturn](https://github.com/coturn/coturn)




## How to use this image

To run Coturn TURN server just start the container: 
```bash
docker run -d -p 3478:3478 -p 49152-65535:49152-65535/udp coturn/coturn
```


### Why so many ports opened?

As per [RFC 5766 Section 6.2], these are the ports that the TURN server will use to exchange media.

You can change them with `min-port` and `max-port` Coturn configuration options:
```bash
docker run -d -p 3478:3478 -p 49160-49200:49160-49200/udp \
       coturn/coturn -n --log-file=stdout \
                        --external-ip='$(detect-external-ip)' \
                        --min-port=49160 --max-port=49200
```

Or just use the host network directly (__recommended__, as Docker [performs badly with large port ranges][7]):
```bash
docker run -d --network=host coturn/coturn
```


### Configuration

By default, default Coturn configuration and CLI options provided in the `CMD` [Dockerfile][d1] instruction are used.

1. You may either specify your own configuration file instead.

    ```bash
    docker run -d --network=host \
               -v $(pwd)/my.conf:/etc/coturn/turnserver.conf \
           coturn/coturn
    ```

2. Or specify command line options directly.

    ```bash
    docker run -d --network=host coturn/coturn \
               -n --log-file=stdout \
               --min-port=49160 --max-port=49200 \
               --lt-cred-mech --fingerprint \
               --no-multicast-peers --no-cli \
               --no-tlsv1 --no-tlsv1_1 \
               --realm=my.realm.org \  
    ```
    
3. Or even specify another configuration file.

    ```bash
    docker run -d --network=host  \
               -v $(pwd)/my.conf:/my/coturn.conf \
           coturn/coturn -c /my/coturn.conf
    ```

#### Automatic detection of external IP

`detect-external-ip` binary may be used to automatically detect external IP of TURN server in runtime. It's okay to use it multiple times (the value will be evaluated only once).
```bash
docker run -d --network=host coturn/coturn \
           -n --log-file=stdout \
           --external-ip='$(detect-external-ip)' \
           --relay-ip='$(detect-external-ip)'
```

By default, [IPv4] address is discovered. In case you need an [IPv6] one, specify the `--ipv6` flag:
```bash
docker run -d --network=host coturn/coturn \
           -n --log-file=stdout \
           --external-ip='$(detect-external-ip --ipv6)' \
           --relay-ip='$(detect-external-ip --ipv6)'
```


### Persistence

By default, Coturn Docker image persists its data in `/var/lib/coturn/` directory.

You can speedup Coturn simply by using tmpfs for that:
```bash
docker run -d --network=host --mount type=tmpfs,destination=/var/lib/coturn coturn/coturn
```




## Image versions


### `X`

Latest tag of `X` Coturn's major version.


### `X.Y`

Latest tag of `X` Coturn's minor version.


### `X.Y.Z` or `X.Y.Z.W`

Latest tag version of a concrete `X.Y.Z` or `X.Y.Z.W` version of Coturn.


### `X.Y.Z-rN` or `X.Y.Z.W-rN`

Concrete `N` image revision tag of a Coturn's concrete `X.Y.Z` or `X.Y.Z.W` version.

Once build, it's never updated.


### `alpine`

This image is based on the popular [Alpine Linux project][1], available in [the alpine official image][2]. Alpine Linux is much smaller than most distribution base images (~5MB), and thus leads to much slimmer images in general.

This variant is highly recommended when final image size being as small as possible is desired. The main caveat to note is that it does use [musl libc][4] instead of [glibc and friends][5], so certain software might run into issues depending on the depth of their libc requirements. However, most software doesn't have an issue with this, so this variant is usually a very safe choice. See [this Hacker News comment thread][6] for more discussion of the issues that might arise and some pro/con comparisons of using Alpine-based images.


### `edge`

Contains build of Coturn's latest `master` branch.




## License

Coturn and its Docker images are licensed under [this license][90].

As with all Docker images, these likely also contain other software which may be under other licenses (such as Bash, etc from the base distribution, along with any direct or indirect dependencies of the primary software being contained).

As for any pre-built image usage, it is the image user's responsibility to ensure that any use of this image complies with any relevant licenses for all software contained within.




## Issues

We can't notice comments in the [DockerHub] (or other container registries) so don't use them for reporting issue or asking question.


If you have any problems with or questions about this image, please contact us through a [GitHub issue][3].





[DockerHub]: https://hub.docker.com
[IPv4]: https://en.wikipedia.org/wiki/IPv4
[IPv6]: https://en.wikipedia.org/wiki/IPv6
[RFC 5766 Section 6.2]: https://tools.ietf.org/html/rfc5766.html#section-6.2

[1]: http://alpinelinux.org
[2]: https://hub.docker.com/_/alpine
[3]: https://github.com/coturn/coturn/issues
[4]: http://www.musl-libc.org
[5]: http://www.etalabs.net/compare_libcs.html
[6]: https://news.ycombinator.com/item?id=10782897
[7]: https://github.com/instrumentisto/coturn-docker-image/issues/3

[90]: https://github.com/coturn/coturn/blob/master/LICENSE

[d1]: https://github.com/coturn/coturn/blob/master/docker/coturn/debian/Dockerfile
[d2]: https://github.com/coturn/coturn/blob/master/docker/coturn/alpine/Dockerfile
