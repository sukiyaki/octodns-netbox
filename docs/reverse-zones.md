# Create PTR records for a reverse zone

This guide creates PTR records from the IP addresses in NetBox.
It assumes that the names are in NetBox and the source is in your octoDNS config, as [Create A and AAAA records](forward-zones.md) shows.

## Name the zone after the network

The source reads the network from the zone name.
It then creates a PTR record for each IP address in that network.

| Network | Zone name |
| --- | --- |
| `192.0.0.0/16` | `0.192.in-addr.arpa.` |
| `192.0.3.0/24` | `3.0.192.in-addr.arpa.` |
| `192.0.2.1/32` | `1.2.0.192.in-addr.arpa.` |
| `192.0.2.0/26` | `0/26.2.0.192.in-addr.arpa.` or `0-26.2.0.192.in-addr.arpa.` |
| `2001:db8::/32` | `8.b.d.0.1.0.0.2.ip6.arpa.` |
| `2001:db8::/64` | `0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.` |

- An IPv4 zone has one label for each octet of the network: `/8`, `/16`, `/24`, or `/32`.
  The `/32` zone holds the PTR record of one address, at the zone apex.
- A classless IPv4 zone, for a prefix length from 25 to 31, starts with the last octet of the network address and the prefix length.
  `64/26.2.0.192.in-addr.arpa.` is `192.0.2.64/26`.
  `0/26` is the RFC 2317 form, and `0-26` is the RFC 4183 form.
- An IPv6 zone has one hexadecimal digit for each 4 bits of the network, from 1 digit for a `/4` to 32 digits for one address, a `/128`.

The mask of an IP address in NetBox does not matter.
For example, `192.0.2.3/29` gets a PTR record in zone `2.0.192.in-addr.arpa.`.

## Configure an IPv4 reverse zone

The examples in this section use these IP addresses:

| IP address | Description |
| --- | --- |
| `192.0.3.1/24` | `description-192-0-3-1.example.com` |
| `192.0.3.2/24` | `vrf-mgmt-description-192-0-3-2.example.com` |

1. Add the zone to your octoDNS config:

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
     3.0.192.in-addr.arpa.:
       sources:
         - netbox
       targets:
         - yaml
   ```

2. Dump the records that the source creates:

   ```sh
   octodns-dump --config-file config.yaml --output-dir dump 3.0.192.in-addr.arpa. netbox
   ```

   `dump/3.0.192.in-addr.arpa.yaml` holds one PTR record for each IP address:

   ```yaml
   # 3.0.192.in-addr.arpa.yaml
   '1':
     ttl: 60
     type: PTR
     value: description-192-0-3-1.example.com.
   '2':
     ttl: 60
     type: PTR
     value: vrf-mgmt-description-192-0-3-2.example.com.
   ```

## Configure an IPv6 reverse zone

Add the zone in the same way:

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
  0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.:
    sources:
      - netbox
    targets:
      - yaml
```

A PTR record gets the first name in the description that the source can use.
If `2001:db8::1:2/64` has the description `description-host2.subdomain1.example.com,description-host2.subdomain2.example.com`, the zone gets this record:

```yaml
# 0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.yaml
2.0.0.0.1.0.0.0.0.0.0.0.0.0.0.0:
  ttl: 60
  type: PTR
  value: description-host2.subdomain1.example.com.
```

## Give a PTR record every name

To give each PTR record every name in the description, set `multivalue_ptr: true`:

```yaml
providers:
  netbox:
    class: octodns_netbox.NetboxSource
    url: https://netbox.example.com
    token: env/NETBOX_TOKEN
    multivalue_ptr: true
  yaml:
    class: octodns.provider.yaml.YamlProvider
    directory: ./zones

zones:
  0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.:
    sources:
      - netbox
    targets:
      - yaml
```

The record of `2001:db8::1:2` then has both names:

```yaml
# 0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.yaml
2.0.0.0.1.0.0.0.0.0.0.0.0.0.0.0:
  ttl: 60
  type: PTR
  values:
  - description-host2.subdomain1.example.com.
  - description-host2.subdomain2.example.com.
```

## Configure a classless IPv4 zone

1. Add the classless zone to your octoDNS config.
   This config uses the RFC 2317 form:

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
     0/26.2.0.192.in-addr.arpa.:
       sources:
         - netbox
       targets:
         - yaml
   ```

2. Create the directory for the dump.
   octoDNS writes zone `0/26.2.0.192.in-addr.arpa.` to `dump/0/26.2.0.192.in-addr.arpa.yaml`, but it does not create the directory `dump/0`.

   ```sh
   mkdir -p dump/0
   ```

   A `YamlProvider` target needs the same directory, `zones/0` in this config.
   The `0-26` form has no slash and needs no directory.
3. Dump the records that the source creates:

   ```sh
   octodns-dump --config-file config.yaml --output-dir dump 0/26.2.0.192.in-addr.arpa. netbox
   ```

The source names each PTR record with the last octet of the address in front of the zone name.

| Address | PTR record in `0/26.2.0.192.in-addr.arpa.` | PTR record in `0-26.2.0.192.in-addr.arpa.` |
| --- | --- | --- |
| `192.0.2.1` | `1.0/26.2.0.192.in-addr.arpa.` | `1.0-26.2.0.192.in-addr.arpa.` |
| `192.0.2.65` | none, outside `192.0.2.0/26` | none, outside `192.0.2.0/26` |

The source does not create the CNAME records that point from the parent zone, `2.0.192.in-addr.arpa.`, to the classless zone.
Add them where you manage the parent zone.
To manage the parent zone with octoDNS and this source too, see [Configure the parent of a classless zone](#configure-the-parent-of-a-classless-zone).

A classless zone name can have fewer labels.
The other labels give the first octets of the network, as in any reverse zone.
The first label gives the next octet and the prefix length, and the octets after it are 0.
`0/26.0.192.in-addr.arpa.` covers `192.0.0.0/26`, and the PTR record of `192.0.0.5` is `5.0/26.0.192.in-addr.arpa.`.
`64-26.0.192.in-addr.arpa.` covers `192.0.64.0/26`, and the PTR record of `192.0.64.5` is `5.64-26.0.192.in-addr.arpa.`.

## Configure the parent of a classless zone

RFC 2317 puts a CNAME record in the parent zone for each address of the classless zone.
octoDNS rejects a CNAME value that holds a slash, such as `1.0/26.2.0.192.in-addr.arpa.`.
Name the classless zone in the RFC 4183 form, `0-26.2.0.192.in-addr.arpa.`, for this setup.

Give the classless zone a name inside the zone that holds the CNAME records, as `0-26.2.0.192.in-addr.arpa.` is inside `2.0.192.in-addr.arpa.`.
octoDNS finds the sub-zones of a zone by name alone.
`64-26.0.192.in-addr.arpa.` covers the same addresses as `0-26.64.0.192.in-addr.arpa.`, but it is not inside `64.0.192.in-addr.arpa.`.
With the shorter name, octoDNS gives zone `64.0.192.in-addr.arpa.` no sub-zone, and the source cannot tell that the classless zone exists.
That zone then gets a PTR record next to each CNAME record, and octoDNS stops it.

1. Add both zones to your octoDNS config.
   The parent zone reads the CNAME records from a second source, here a `YamlProvider` with the directory `./cnames`:

   ```yaml
   providers:
     netbox:
       class: octodns_netbox.NetboxSource
       url: https://netbox.example.com
       token: env/NETBOX_TOKEN
     cnames:
       class: octodns.provider.yaml.YamlProvider
       directory: ./cnames
     yaml:
       class: octodns.provider.yaml.YamlProvider
       directory: ./zones

   zones:
     2.0.192.in-addr.arpa.:
       sources:
         - netbox
         - cnames
       targets:
         - yaml
     0-26.2.0.192.in-addr.arpa.:
       sources:
         - netbox
       targets:
         - yaml
   ```

2. Write a CNAME record for each address of the classless zone in `cnames/2.0.192.in-addr.arpa.yaml`:

   ```yaml
   '1':
     type: CNAME
     value: 1.0-26.2.0.192.in-addr.arpa.
   '2':
     type: CNAME
     value: 2.0-26.2.0.192.in-addr.arpa.
   ```

octoDNS treats `0-26.2.0.192.in-addr.arpa.` as a sub-zone of `2.0.192.in-addr.arpa.`.
The source reads the network of the sub-zone, `192.0.2.0/26`, and gives the parent zone no PTR record for an address in that network.
octoDNS rejects a CNAME record next to another record of the same name, so a PTR record there would stop the zone.
For each address that it leaves out, the source logs a warning:

```text
Skipping subzone record: 1.2.0.192.in-addr.arpa. PTR, which zone 0-26.2.0.192.in-addr.arpa. holds
```

The parent zone keeps the PTR records of the other addresses, such as `192.0.2.65`.
The source reads the network only from a zone name in the `0/26` or `0-26` form.
For a classless zone with another name, such as `subnet1.2.0.192.in-addr.arpa.`, the parent zone gets the PTR record of every address.

## Fix a PTR record with values from two VRFs

NetBox can hold the same address more than once, for example once in the Global VRF and once in VRF `mgmt`.
The PTR record of that address then gets a value from each NetBox IP address, even with `multivalue_ptr: false`.
When each VRF gives the PTR record one name, and the VRFs give different names, the source logs a warning:

```text
PTR 1.2.0.192.in-addr.arpa. gets a value from each of 2 NetBox IP addresses for 192.0.2.1, in VRFs Global, mgmt. Set populate_vrf_id or populate_vrf_name to read one VRF.
```

Do one of these:

- To read one VRF, set `populate_vrf_id` or `populate_vrf_name`, as [Read one VRF](filter-by-vrf-and-tag.md#read-one-vrf) shows.
- To keep the values from every VRF, set `multivalue_ptr: true`.
  The source does not log the warning with that setting.

The source logs no warning when two NetBox IP addresses in one VRF have the same address and different names, even when other VRFs hold the address too.
The PTR record gets a value from each of them, and reading that VRF still gives it two values.
To give it one value, remove the extra IP address in NetBox.

## Fix the error "must be one hex digit"

Each label of an IPv6 reverse zone is one hexadecimal digit.
For a zone such as `db8.1.0.0.2.ip6.arpa.`, octoDNS stops with this error before the source sends a request to NetBox:

```text
ValueError: Invalid reverse zone 'db8.1.0.0.2.ip6.arpa.'. Each label before '.ip6.arpa.' is one nibble, so 'db8' must be one hex digit.
```

Rename the zone so that each label is one digit.
For `2001:db8::/32`, the zone is `8.b.d.0.1.0.0.2.ip6.arpa.`.
