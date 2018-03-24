[![Build Status](https://travis-ci.org/kvic-z/pixelserv-tls.svg?branch=master)](https://travis-ci.org/kvic-z/pixelserv-tls)


_pixelserv-tls_ is a tiny bespoke HTTP/1.1 webserver with HTTPS and SNI support. It acts on behalf of hundreds of thousands of advert/tracker servers and responds to all requests with  nothing  to  speeds  up  web browsing.

_pixelserv-tls_  supports TLSv1.0 and TLSv1.2 and thus could operate with a wide range of browsers and client devices.  Server  certificates  for any  given  advert/tracker domains are generated automatically on first use and saved to disk.

pixelserv-tls can log access and HTTP/1.1 POST contents to syslog. So it  is  also  a  useful  tool  to  inspect and expose 'wrongly blocked' domains as well as 'rogue' domains invading user privacy.

### Build from source

This works on all Linux distributions and Linux-like environments such Homebrew for macOS and Cygwin for Windows.

````
autoreconf -i
./configure
make install
````

### Install on Entware

Pre-built binaries are distributed by Entware team. Beta binaries during development cycles are distributed from this GitHub repository.

#### Install pre-built binaries
````
opkg install pixelserv-tls
````

#### Install beta binaries
````
sh -c "$(wget -qO - https://kazoo.ga/pixelserv-tls/install-beta.sh)"
````

### Install from AUR on Arch Linux

This also works on all Arch Linux derived distributions such as Manjaro, Antergos and Chakra.

#### Install pre-built binaries using `yaourt`
````
yaourt -S pixelserv-tls
````
#### Build from source package
````
git clone https://aur.archlinux.org/pixelserv-tls.git
cd pixelserv-tls
makepkg -si
````

### Launch pixelserv-tls
````
pixelserv-tls <listening ip>
````

Check out this [page](https://github.com/kvic-z/pixelserv-tls/wiki/Command-Line-Options) for details of command line options.

### Announcement/discussion

* https://kazoo.ga/pixelserv-tls/
* A pixelserv-tls chit-chat [thread](http://www.snbforums.com/threads/pixelserv-a-better-one-pixel-webserver-for-adblock.26114) on SNBfourms.

