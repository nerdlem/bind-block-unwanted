# BIND unwanted domains blocker

Fetch various blocklists and generate a BIND zone from them.

Configure BIND to redirect to `drop.sinkhole` (walled garden) for ad, tracking and malicious domains to stop clients from contacting them.

Requires BIND 9.8 or newer for [RPZ](https://en.wikipedia.org/wiki/Response_policy_zone) support.

Uses the following sources:

* [Peter Lowe’s Ad and tracking server list](https://pgl.yoyo.org/adservers/)
* [Malware domains](http://www.malwaredomains.com/)
* [MVPS HOSTS](http://winhelp2002.mvps.org/)
* [Adaway default blocklist](https://adaway.org/hosts.txt)
* [hpHosts](https://hosts-file.net/)
* [Dan Pollock’s hosts file](http://someonewhocares.org/hosts/zero/)
* [MalwareDomainList.com Hosts List](https://www.malwaredomainlist.com/hostslist/hosts.txt)
* [StevenBlack Unified hosts file](https://github.com/StevenBlack/hosts)
* [CAMELEON](http://sysctl.org/cameleon/)
* [ZeuS domain blocklist (Standard)](https://zeustracker.abuse.ch/blocklist.php)
* [Disconnect.me](https://disconnect.me/)
* [The Big Blocklist Collection](https://v.firebog.net)
* [OpenPhish](https://openphish.com)
* [Free Ads BL from SquidBlacklist](http://www.squidblacklist.org)

and more

## Setup

### Python packages

* [requests](https://pypi.python.org/pypi/requests)
* [dnspython](https://pypi.python.org/pypi/dnspython)

These packages need to be installed to run the update script.

### Configure BIND

Create a local domain (`.sinkhole`) for the sinkhole. Replace `192.168.1.220` with the IP address of your sinkhole server.
```
@ 8600 IN SOA  .sinkhole root.sinkhole. (201702121 604800 86400 2419200 604800 )
@ 8600 IN NS   LOCALHOST.
@ IN A 192.168.1.220
* A 192.168.1.220
```
Add the newly created domain `.sinkhole` zone to the BIND configuration

```
zone "sinkhole." {
        type master;
        file "/var/named/db.sinkhole";
        allow-update { none; };
        allow-transfer { none; };
        allow-query { trusted-acl;};
};
```
Add the `response-policy` statement to the BIND options

```
// Blacklist RPZ
response-policy {
	zone "rpz.blacklist";
};
```

Add your RPZ zone.

```
// Blacklist zone
zone "rpz.blacklist" {
        type master;
        file "/var/named/db.rpz.blacklist";
        allow-update { none; };
        allow-transfer { none; };
        allow-query { none; };
};
```

## Usage

    update-zonefile.py zonefile origin

* zonefile: Path to the zone file to update
* origin: Zone origin to use

Example: `python3 update-zonefile.py /var/named/db.rpz.blacklist rpz.blacklist`

Verification of the zone file with `named-checkzone`:
```
[root@localhost]# named-checkzone admin /var/named/db.rpz.blacklist
/var/named/db.rpz.blacklist:3: using RFC1035 TTL semantics
zone admin/IN: loaded serial 201702126
OK
```
