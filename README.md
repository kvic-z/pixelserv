_pixelserv-tls_ is a tiny bespoke HTTP/1.1 webserver with HTTPS support that acts on behalf of hundreds of thousands of adverts/tracker servers. It responds to all requests with nothing and can be configured to capture what ad networks and trackers intend to send them about you.

_pixelserv-tls_ supports TLS1.2 for HTTPS. Server certificates for domains are automatically generated on demand and on the first request. It can output access log and HTTP POST contnets to syslog. _pixelserv-tls_ is a useful tool to inspect and whitelist domains aggressively adblocked and giving trouble in loading a webpage.

Best of of all _pixelserv-tls_ accelerates web browsing! Check out the numbers [here](https://kazoo.ga/pixelserv-tls-more-is-less/).

### Install from source

````
autoreconf -i
./configure
make install
````
#### Launch pixelserv-tls
````
pixelserv-tls <listening ip>
````

### Install pre-built binaries from Entware-ng
````
opkg install pixelserv-tls
````

Check out this [page](/pixelserv-tls/wiki/Command-Line-Options) for details of command line options.

### Install beta versions on Entware-ng systems
````
sh -c "$(wget -qO - https://kazoo.ga/pixelserv-tls/install-beta.sh)"
````

### Announcement and discussion

* https://kazoo.ga/pixelserv-tls/
* [pixelserv-tls on snb]: A pixelserv-tls chit-chat thread on SNBfourms.

[pixelserv-tls on snb]: <http://www.snbforums.com/threads/pixelserv-a-better-one-pixel-webserver-for-adblock.26114>
