# Create A and AAAA records for a forward zone

This guide creates the A and AAAA records of zone `example.com.` from the IP addresses in NetBox.
It assumes that you installed octodns-netbox and put a NetBox API token in the environment variable `NETBOX_TOKEN`, as the [README](../README.md#quick-start) shows.

## Put the names in NetBox

1. Open each IP address in NetBox.
2. Write the names of the address in its **Description**, separated by commas.
   Write each name as an FQDN, with or without the final dot.
   Case does not matter.

The examples in this guide use these IP addresses.
Each row lists the IP addresses that share a description.

| IP addresses | Description |
| --- | --- |
| `192.0.4.1/24`, `2001:db8::1:1/64` | `description-host1.example.com` |
| `192.0.4.3/24`, `2001:db8::1:3/64` | `description-host3.subdomain1.example.com.jp,description-host3.subdomain2.example.com` |
| `192.0.4.5/24`, `192.0.4.6/24`, `2001:db8::1:5/64`, `2001:db8::1:6/64` | `description-roundrobin.example.com` |
| `2001:db8::1:7/64` | `example.com` |

## Configure the zone

Add the zone to your octoDNS config with the source in `sources`:

```yaml
providers:
  netbox:
    class: octodns_netbox.NetboxSource
    url: https://netbox.example.com
    token: env/NETBOX_TOKEN
  yaml:
    class: octodns.provider.yaml.YamlProvider
    directory: ./zones

zones:
  example.com.:
    sources:
      - netbox
    targets:
      - yaml
```

## Check the records

1. Dump the records that the source creates:

   ```sh
   octodns-dump --config-file config.yaml --output-dir dump example.com. netbox
   ```

2. Open `dump/example.com.yaml`.
   It holds these records, among others:

   ```yaml
   # example.com.yaml
   '':
     ttl: 60
     type: AAAA
     value: 2001:db8::1:7
   description-host1:
   - ttl: 60
     type: A
     value: 192.0.4.1
   - ttl: 60
     type: AAAA
     value: 2001:db8::1:1
   description-host3.subdomain2:
   - ttl: 60
     type: A
     value: 192.0.4.3
   - ttl: 60
     type: AAAA
     value: 2001:db8::1:3
   description-roundrobin:
   - ttl: 60
     type: A
     values:
     - 192.0.4.5
     - 192.0.4.6
   - ttl: 60
     type: AAAA
     values:
     - 2001:db8::1:5
     - 2001:db8::1:6
   ```

   - The name `example.com` gives the record at the zone apex, `''`.
   - IP addresses with the same name share one record, with one value for each address.
     NetBox keeps the inside and the outside address of a NAT as two IP addresses.
     When both have the same name, the A record gets both addresses.
     To publish one of them, remove the name from the other.
   - `description-host3.subdomain1.example.com.jp` is not in the zone, so it gets no record.

## Read the names from `dns_name`

NetBox has a **DNS name** field, `dns_name`, that holds one name.
To read it instead of the description, set `field_name: dns_name`:

```yaml
providers:
  netbox:
    class: octodns_netbox.NetboxSource
    url: https://netbox.example.com
    token: env/NETBOX_TOKEN
    field_name: dns_name
  yaml:
    class: octodns.provider.yaml.YamlProvider
    directory: ./zones

zones:
  example.com.:
    sources:
      - netbox
    targets:
      - yaml
```

If `192.0.4.1/24` and `2001:db8::1:1/64` have the DNS name `dnsname-host1.example.com`, the zone gets this record:

```yaml
# example.com.yaml
dnsname-host1:
- ttl: 60
  type: A
  value: 192.0.4.1
- ttl: 60
  type: AAAA
  value: 2001:db8::1:1
```

## Leave out names in subdomains

By default, the zone gets records for names in its subdomains, such as `description-host3.subdomain2`.
To create records only for names one label below the zone, set `populate_subdomains: false`:

```yaml
providers:
  netbox:
    class: octodns_netbox.NetboxSource
    url: https://netbox.example.com
    token: env/NETBOX_TOKEN
    populate_subdomains: false
  yaml:
    class: octodns.provider.yaml.YamlProvider
    directory: ./zones

zones:
  example.com.:
    sources:
      - netbox
    targets:
      - yaml
```

The zone keeps `description-host1`, `description-roundrobin`, and the apex record.
It loses `description-host3.subdomain2`.

## Put a subdomain in its own zone

When a subdomain is a zone of its own, add both zones to the config.
octoDNS then treats `subdomain1.example.com.` as a sub-zone of `example.com.`.

```yaml
providers:
  netbox:
    class: octodns_netbox.NetboxSource
    url: https://netbox.example.com
    token: env/NETBOX_TOKEN
  yaml:
    class: octodns.provider.yaml.YamlProvider
    directory: ./zones

zones:
  example.com.:
    sources:
      - netbox
    targets:
      - yaml
  subdomain1.example.com.:
    sources:
      - netbox
    targets:
      - yaml
```

The source puts each name in the zone it belongs to.
Take these IP addresses:

| IP addresses | Description |
| --- | --- |
| `192.0.4.2/24`, `2001:db8::1:2/64` | `description-host2.subdomain1.example.com,description-host2.subdomain2.example.com` |
| `192.0.4.4/24` | `subdomain1.example.com` |

Zone `subdomain1.example.com.` gets these records:

```yaml
# subdomain1.example.com.yaml
'':
  ttl: 60
  type: A
  value: 192.0.4.4
description-host2:
- ttl: 60
  type: A
  value: 192.0.4.2
- ttl: 60
  type: AAAA
  value: 2001:db8::1:2
```

Zone `example.com.` gets the record `description-host2.subdomain2`, but no record for the names in `subdomain1.example.com.`.
For each record that it leaves out, the source logs a warning that starts with `Skipping subzone record:`:

```text
Skipping subzone record: description-host2.subdomain1.example.com. A, which zone subdomain1.example.com. holds
```

The source leaves out these names before it checks them.
A name in `subdomain1.example.com.` that octoDNS rejects, or that the source cannot use, such as `a..subdomain1.example.com` with its empty label, therefore gives only this warning in zone `example.com.`, and the warning that names the reason in zone `subdomain1.example.com.`.
The source leaves out the names also when the zone is lenient, where octoDNS would add the records to `example.com.`.
A reverse zone leaves out the PTR records of a configured reverse zone inside it in the same way.
