# Metrics setup

It is need the following libraries:

- libprom
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

- [libprom](https://github.com/jelmd/libprom)

Download from https://github.com/jelmd/libprom.git

```
git clone https://github.com/jelmd/libprom.git
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

- Build libprom from source code

```
git clone https://github.com/jelmd/libprom.git
cd libprom
make
```
