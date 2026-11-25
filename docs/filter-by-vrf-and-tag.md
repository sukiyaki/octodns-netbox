# Read one VRF or tagged IP addresses

By default, the source reads the IP addresses in every VRF, with or without tags.
It reads IP addresses of every status: active, reserved, deprecated, DHCP, and SLAAC.
This guide limits the source to one VRF, to tagged IP addresses, or to both.

The examples use these IP addresses:

| IP address | VRF | Tags | Description |
| --- | --- | --- | --- |
| `192.0.3.1/24` | Global | none | `description-192-0-3-1.example.com` |
| `192.0.3.2/24` | `mgmt` | none | `vrf-mgmt-description-192-0-3-2.example.com` |
| `192.0.5.1/24` | Global | `dns` | `tagged-dns.example.org` |
| `192.0.5.2/24` | Global | `dns`, `external` | `tagged-dns-external.example.org` |
| `192.0.5.3/24` | Global | none | `untagged.example.org` |

NetBox calls the IP addresses that have no VRF the Global VRF.

## Read one VRF

Select the VRF by its ID or by its name.

### Select the VRF by ID

1. In NetBox, open the VRF.
   The ID is the number at the end of its URL, such as `/ipam/vrfs/1/`.
2. Set `populate_vrf_id` to the ID:

   ```yaml
   providers:
     netbox:
       class: octodns_netbox.NetboxSource
       url: https://netbox.example.com
       token: env/NETBOX_TOKEN
       populate_vrf_id: 1
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

If VRF 1 is `mgmt`, the zone gets only the record of `192.0.3.2`:

```yaml
# 3.0.192.in-addr.arpa.yaml
'2':
  ttl: 60
  type: PTR
  value: vrf-mgmt-description-192-0-3-2.example.com.
```

### Select the VRF by name

Set `populate_vrf_name` to the name of the VRF:

```yaml
providers:
  netbox:
    class: octodns_netbox.NetboxSource
    url: https://netbox.example.com
    token: env/NETBOX_TOKEN
    populate_vrf_name: mgmt
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

At startup, the source asks NetBox for the ID of the VRF with that name.
The zone then gets the same record as with `populate_vrf_id: 1`.

If no VRF has the name, or more than one VRF has it, octoDNS stops with an error.
For `populate_vrf_name: no-such-vrf`, the error is:

```text
ValueError: Failed to retrieve VRF information by name 'no-such-vrf'. Use a valid populate_vrf_id instead.
```

Set `populate_vrf_id` instead when several VRFs share the name, or when the VRF is named `null`.
NetBox reads the filter `name=null` as an empty name, so the source finds no VRF named `null`.

## Read only IP addresses without a VRF

Set `populate_vrf_id: 0` or `populate_vrf_name: Global`:

```yaml
providers:
  netbox:
    class: octodns_netbox.NetboxSource
    url: https://netbox.example.com
    token: env/NETBOX_TOKEN
    populate_vrf_id: 0
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

The zone gets only the record of `192.0.3.1`:

```yaml
# 3.0.192.in-addr.arpa.yaml
'1':
  ttl: 60
  type: PTR
  value: description-192-0-3-1.example.com.
```

## Read only tagged IP addresses

Set `populate_tags` to a list of tag slugs.
NetBox shows the slug on the page of each tag.
Write each slug as NetBox shows it.
For a slug that no tag has, NetBox answers `400 Bad Request`, and the zone stops.

```yaml
providers:
  netbox:
    class: octodns_netbox.NetboxSource
    url: https://netbox.example.com
    token: env/NETBOX_TOKEN
    populate_tags:
      - dns
  yaml:
    class: octodns.provider.yaml.YamlProvider
    directory: ./zones

zones:
  example.org.:
    sources:
      - netbox
    targets:
      - yaml
```

The zone gets the records of the two IP addresses with tag `dns`:

```yaml
# example.org.yaml
tagged-dns:
  ttl: 60
  type: A
  value: 192.0.5.1
tagged-dns-external:
  ttl: 60
  type: A
  value: 192.0.5.2
```

With more than one tag in the list, the source reads only the IP addresses that have every tag.
With `populate_tags: [dns, external]`, the zone gets only `tagged-dns-external`.

## Combine a VRF and tags

Set a VRF key and `populate_tags` together.
The source then reads only the IP addresses in that VRF that have every tag.

## Leave out IP addresses by status

The source has no setting for the status of an IP address, and sends no status filter to NetBox.
A reserved or deprecated IP address with a name gets its records, as an active one does.
To leave such IP addresses out, give a tag to the IP addresses that need records and set `populate_tags`, or remove the name from the others.
