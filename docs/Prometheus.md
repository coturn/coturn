# Prometheus setup

It is need the following libraries:

- prometheus-client-c
- libmicrohttpd

## UDP 401 mitigation metrics

When the optional UDP 401 response rate limit is enabled, use:

```
401-ratelimit
401-req-limit=1000
401-window=120
prometheus
```

The rate limit is disabled by default. It applies only to UDP `401 Unauthorized`
responses, which can otherwise be used in spoofed-source reflection attacks.

When Prometheus is enabled, the exporter provides the following counters for
this path whether or not mitigation is enabled. The dropped response counter
increments only when `401-ratelimit` suppresses responses.

| Metric | Meaning |
|---|---|
| `turn_unauthenticated_401_requests` | UDP requests requiring a `401 Unauthorized` response. |
| `turn_unauthenticated_401_responses` | UDP `401 Unauthorized` responses emitted. |
| `turn_unauthenticated_401_dropped_responses` | UDP `401` responses suppressed by DDoS mitigation. |

## Ubuntu

### Install libmicrohttpd

```
sudo apt install libmicrohttpd-dev 
```

## Install From source code

- [libmicrohttpd](https://www.gnu.org/software/libmicrohttpd/)

Download from https://git.gnunet.org/libmicrohttpd.git

```
git clone https://git.gnunet.org/libmicrohttpd.git
```

- [prometheus-client-c](https://github.com/digitalocean/prometheus-client-c)

Download from https://github.com/digitalocean/prometheus-client-c.git

```
git clone https://github.com/digitalocean/prometheus-client-c.git
```

## Build

- Build libmicrohttpd from source code

```
git clone https://git.gnunet.org/libmicrohttpd.git
cd libmicrohttpd
./autogen.sh
./configure --prefix=`pwd`/install --disable-doc --disable-examples \
    --disable-tools
make install
```

- Build prometheus-client-c from source code

```
git clone https://github.com/digitalocean/prometheus-client-c.git
cd prometheus-client-c
make
```
