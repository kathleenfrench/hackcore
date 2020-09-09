# scanning cheats/one-offs

- [ips](#ips)
  * [extracting live ips](#extracting-live-ips-from-nmap-scan)
- [dns](#dns)
  * [lookups](#dns-lookups)
  * [zone-transfers](#zone-transfers)
  * [brute-force](#brute-force)
- [port knocking](#port-knocking)


---

# ips

## extracting live ips from nmap scan

```
nmap [TARGET IP] --open -oG scan-results; cat scan-results | grep "/open" | cut -d " " -f 2 > exposed-services-ips
```

# dns

## dns lookups

```
whois domain.com
dig {a|txt|ns|mx} domain.com
host -t {a|txt|ns|mx} megacorpone.com
```

## zone transfers

_what is a zone transfer?_

> zone transfer is the process of copying the contents of the zone file on a primary DNS server to a secondary DNS server. using zone transfer provides fault tolerance by synchronizing the zone file in a primary DNS server with the zone file in a secondary DNS server.

```
host -l megacorpone.com ns1.megacorpone.com
dig {a|txt|ns|mx} domain.com @ns1.domain.com
dnsrecon -d megacorpone.com -t axfr @ns2.megacorpone.com
```

## brute force

```
host -a megacorpone.com
dnsenum domain.com
nslookup -> set type=any -> ls -d domain.com
for sub in $(cat subdomains.txt);do host $sub.domain.com|grep "has.address";done
```

### tools

**`host`**:

|flag|descripton|
|----|---|
|`-a`| The -a (all) option is equivalent to setting the -v option and asking host to make a query of type ANY.|
|`-t`| The -t option is used to select the query type. The type can be any recognized query type: CNAME, NS, SOA, SIG, KEY, AXFR, etc. When no query type is specified, host automatically selects an appropriate query type. By default, it looks for A, AAAA, and MX records, but if the -C option was given, queries will be made for SOA records, and if name is a dotted-decimal IPv4 address or colon-delimited IPv6 address, host will query for PTR records. If a query type of IXFR is chosen the starting serial number can be specified by appending an equal followed by the starting serial number (e.g., -t IXFR=12345678).|
|`-l`|List mode is selected by the -l option. This makes host perform a zone transfer for zone name. Transfer the zone printing out the NS, PTR, and address records (A/AAAA). If combined with -a all records will be printed.|

**`whois`**:

> when a WHOIS search is performed, the service queries several domain registrars since there is no central database to display the final results


# port knocking

```
for x in 7000 8000 9000; do nmap -Pn –host_timeout 201 –max-retries 0 -p $x [TARGET IP]; done
```

