# Prometheus setup

It is need the following libraries:

- prometheus-client-c
- libmicrohttpd

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
