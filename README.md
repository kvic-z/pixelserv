[![Build Status](https://travis-ci.org/kvic-z/pixelserv-tls.svg?branch=master)](https://travis-ci.org/kvic-z/pixelserv-tls)

_pixelserv-tls_ is a tiny bespoke HTTP/1.1 webserver with HTTPS support that acts on behalf of hundreds of thousands of adverts/tracker servers. It responds to all requests with nothing and can be configured to capture what ad networks and trackers intend to send them about you.

_pixelserv-tls_ supports TLS1.2 for HTTPS. Server certificates for domains are automatically generated on demand and on the first request. It can output access log and HTTP POST contents to syslog. _pixelserv-tls_ is a useful tool to inspect and whitelist domains aggressively adblocked and giving trouble in loading a webpage.

Best of of all _pixelserv-tls_ accelerates web browsing! Check out the numbers [here](https://kazoo.ga/pixelserv-tls-more-is-less/).

### Install from source

````
autoreconf -i
./configure
make install
````

### Install pre-built binaries from Entware-ng
````
opkg install pixelserv-tls
````

### Install beta version on Entware-ng systems
````
sh -c "$(wget -qO - https://kazoo.ga/pixelserv-tls/install-beta.sh)"
````

### Install from AUR on Arch Linux/Manjaro/Antergos/Chakra and other Arch based distributions
#### Using `yaourt`
````
yaourt -S pixelserv-tls
````
#### Manual
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

