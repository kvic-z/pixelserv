## pixelserv-tls
_pixelserv-tls_ is a tiny bespoke HTTP/1.1 webserver with HTTPS support that acts on behalf of hundreds of thousands of adverts/tracker servers. It responds to all requests with nothing and can be configured to capture what ad networks and trackers intend to send them about you.

pixelserv-tls supports TLS1.2 for HTTPS. Server certificates for domains are automatically generated on demand and on the first request. It can output access log and HTTP POST contnets to syslog. pixelserv-tls is a useful tool to inspect and whitelist domains aggressively adblocked and giving trouble in loading a webpage.

Best of of all pixelserv-tls speeds up web browsing! Check out the numbers [here](https://kazoo.ga/pixelserv-tls-more-is-less/).

### Install from source

#### Check out the git repo and then:
````
autoreconf -i
./configure
make install
````
#### Launch pixelserv-tls

A few examples:
* `pixelserv-tls`
* `pixelserv-tls 192.168.1.1`

### Install pre-built binaries

Binaries are available from [Entware-ng](/Entware-ng/Entware-ng).

````
opkg install pixelserv-tls
````

Check out this [page](/pixelserv-tls/wiki/Command-Line-Options) for details of command line options.

### Access the servstats page

* http://<your listening ip>/servstats

Check out the [sample servstats page](/kvic-z/pixelserv-tls/wiki/pixelserv‑tls-servstats).


### Announcement and Discussion

* https://kazoo.ga/pixelserv-tls/


### Other References
* [pixelserv-tls on snb]: A pixelserv-tls chit-chat thread on SNBfourms.
* [pixelserv]: An old pixelserv thread on LinksysInfo.org
* [pixelserv-ddwrt]: An even older thread of an early version of pixelserv.

[pixelserv-tls on snb]: <http://www.snbforums.com/threads/pixelserv-a-better-one-pixel-webserver-for-adblock.26114>
[pixelserv]: <http://www.linksysinfo.org/index.php?threads/pixelserv-compiled-to-run-on-router-wrt54g.30509/page-3#post-229342>
[pixelserv-ddwrt]: <http://www.dd-wrt.com/phpBB2/viewtopic.php?p=685201>
