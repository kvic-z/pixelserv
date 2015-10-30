pixelserv
=========

Tiny webserver that responds to all requests with "nothing".  Particularly useful for network connections with high latency and metered bandwidth.

This fork adds HTTPS support. Certificates for adserver domains are automatically generated at real-time upon first access.

Binaries
--------

Binary releases are available in the following flavors:
* MIPS for Asuswrt/Merlin:
  * Built via brcm uclibc cross-compiler toolchain from Asuswrt-Merlin
* ARM for Asuswrt/Merlin:
  * Built via brcm uclibc cross-compiler toolchain from Asuswrt-Merlin
* Entware-ARM
  * Built via glibc cross-compiler toolchain from Entware-ARM

Stats
-----

Stats are viewable by default at http://pixelservip/servstats.txt (for raw text format) or http://pixelservip/servstats for html format), where pixelserv ip is the ip address that pixelserv is listening on.

Explanation of stats:
* uts: uptime in seconds
* req: number of connection requests
* avg: average request size in bytes
* rmx: maximum request size in bytes
* tav: average request processing time in milliseconds
* tmx: maximum request processing time in milliseconds
* err: number of connections resulting in processing errors (syslog may have details)
* tmo: number of connections that timed out while trying to read a request from the client
* cls: number of connections that were closed by the client while reading or replying to the request
* nou: number of requests that failed to include a URL
* pth: number of requests for a path that could not be parsed
* nfe: number of requests for a file with no extension
* ufe: number of requests for an unrecognized/unhandled file extension
* gif: number of requests for GIF images
* bad: number of requests for unrecognized/unhandled HTTP methods
* txt: number of requests for plaintext data formats
* jpg: number of requests for JPEG images
* png: number of requests for PNG images
* swf: number of requests for Adobe Shockwave Flash files
* ico: number of requests for ICO files (usually favicons)
* slh: number of HTTPS requests with a good certifcate (cert exists and used) 
* slm: number of HTTPS requests without a certficate (cert missing for ad domain)
* sle: number of HTTPS requests with a bad cert (error in existing cert)
* slu: number of unrecognized HTTPS requests (none of slh/slm/sle)
* sta: number of requests for HTML stats
* stt: number of requests for plaintext stats
* 204: number of requests for /generate_204 URLs
* rdr: number of requests resulting in a redirect
* pst: number of requests for HTTP POST method
* hed: number of requests for HTTP HEAD method

Sources
-------

* http://www.snbforums.com/threads/pixelserv-a-better-one-pixel-webserver-for-adblock.26114
* http://www.linksysinfo.org/index.php?threads/pixelserv-compiled-to-run-on-router-wrt54g.30509/page-3#post-229342
* http://www.dd-wrt.com/phpBB2/viewtopic.php?p=685201
