#  A [NetBox](https://github.com/digitalocean/netbox) source for [octoDNS](https://github.com/github/octodns/)

[![PyPI](https://img.shields.io/pypi/v/octodns-netbox)](https://pypi.python.org/pypi/octodns-netbox)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/octodns-netbox)](https://pypi.python.org/pypi/octodns-netbox)
[![PyPI - License](https://img.shields.io/pypi/l/octodns-netbox)](LICENSE)

This project provides a NetBox source for OctoDNS. It retrieves IP address information from NetBox so that OctoDNS creates corresponding A/AAAA and PTR records.

**Note:** This is just a **source** for OctoDNS, not a **provider**. It only serve to populate records into a zone, cannot be synced to.

## Installation

```
pip install octodns-netbox
```

## Getting started

You must configure the `url` and `token` parameters in your YAML file to work with the NetBox API. You can also specify the TTL (Time to Live) for the generated records, but this parameter is optional, and the default value is 60.

```yaml
providers:
  netbox:
    class: octodns_netbox.NetboxSource
    url: https://ipam.example.com
    token: env/NETBOX_TOKEN
    ttl: 60
```

### A records / AAAA records

To create A/AAAA records for octoDNS, you need to manage the mapping between IP addresses and fully qualified domain names (FQDNs) in NetBox. The `description` field is used for this purpose, and it should contain a comma-separated list of hostnames (FQDNs).

Starting with [Netbox v2.6.0](https://github.com/netbox-community/netbox/issues/166), Netbox now has a `dns_name` field in IP address records. But we **do not** use this field by default because this `dns_name` field can only store **single** FQDN. To use a `dns_name` field, set `field_name: dns_name` in [the configuration](#examples).

`field_name` also accepts a list of field names, e.g. `field_name: [dns_name, description]`. When a list is given, A/AAAA records are produced from the deduplicated union of FQDNs parsed from every listed field — so one IP can carry a canonical FQDN in `dns_name` **and** additional aliases in `description`, and all become A/AAAA records. See the [list-form section](#multi-field-field_name) for details.

### Custom fields

You can also use NetBox custom fields to store DNS names. This is useful when you want to keep the `dns_name` field for the primary hostname and use a custom field for additional aliases.

To use a custom field, prefix the field name with `cf_`. For example, if you have a custom field named `additional_dns` on IP addresses, configure it as:

```yaml
providers:
  netbox-aliases:
    class: octodns_netbox.NetboxSource
    url: https://ipam.example.com
    token: env/NETBOX_TOKEN
    field_name: cf_additional_dns
```

The custom field should contain comma-separated FQDNs, just like the `description` field. Custom fields compose with the list form: any entry in a list-valued `field_name` may be a `cf_*` custom field, e.g. `field_name: [dns_name, cf_additional_dns]`.

### PTR records

`octodns-netbox` also supports PTR records. By default, only the first FQDN in the field is used to generate the PTR record, but you can enable multiple PTR records for a single IP by setting the `multivalue_ptr` parameter to `true` in [the configuration](#examples).

#### Example (`multivalue_ptr: false` - default)
- IP Address: `192.0.2.1/24`
  - Description: `en0.host1.example.com,host1.example.com`
- DNS Zone: `2.0.192.in-addr.arpa.`
  - `1. PTR en0.host1.example.com.`

#### 🔍 Example (`multivalue_ptr: true`)
- IP Address: `192.0.2.1/24`
  - Description: `en0.host1.example.com,host1.example.com`
- DNS Zone: `2.0.192.in-addr.arpa.`
  - `1. PTR en0.host1.example.com.`
  - `1. PTR host1.example.com.`

### Multi-field `field_name`

`field_name` accepts either a single field name (string, the default `description`) or a list of field names. When a list is given, the source reads from every listed field and produces records from the **union** of the FQDNs it finds.

The fields in the list have an ordering: the **first field is the primary**. The primary field is what the NetBox API is queried against for the server-side filter (`__ic=<zone>` / `__empty=false`), and it is the sole source for single-valued PTR records (when `multivalue_ptr: false`, which is the default). Every field contributes to forward A/AAAA records and to multi-valued PTR records.

This means one IP record in NetBox can produce a single canonical PTR (from `dns_name`) **and** multiple A/AAAA records (from `dns_name` *and* `description` aliases), all from a single `NetboxSource` instance.

#### Example: one PTR + multiple A records from a single IP

Assume an IP address in NetBox:
- IP: `192.0.2.1/24`
- `dns_name`: `host.example.com`
- `description`: `alias-a.example.com, alias-b.example.com`

With `field_name: [dns_name, description]` and `multivalue_ptr: false` (default), the resulting records are:

- Forward zone `example.com.`:
  - `host       A  192.0.2.1`
  - `alias-a    A  192.0.2.1`
  - `alias-b    A  192.0.2.1`
- Reverse zone `2.0.192.in-addr.arpa.`:
  - `1  PTR  host.example.com.`  *(from `dns_name` only — single canonical name)*

#### Semantics summary

| Context                                    | Fields consulted | FQDNs taken                                      |
|--------------------------------------------|------------------|--------------------------------------------------|
| PTR with `multivalue_ptr: false` (default) | all fields       | first FQDN of the deduplicated union (in order)  |
| PTR with `multivalue_ptr: true`            | all fields       | deduplicated union                               |
| Forward A/AAAA                             | all fields       | deduplicated union                               |

For single-valued PTR (the default), fields are consulted in order — the first non-empty field that yields an FQDN wins, so primary `dns_name` takes precedence over fallback fields.

#### NetBox API filter scope

The source issues one NetBox `ipam.ip_addresses.filter(...)` call per configured field and unions the results, deduplicated by IP address ID. An IP is fetched if **any** configured field's per-field filter matches (`<field>__ic=<zone>` for forward zones, `<field>__empty=false` for reverse zones). This means an IP whose primary field is empty but whose secondary field carries an in-zone FQDN **is** fetched and contributes records.

Backwards compatibility: omitting `field_name` entirely, or setting it to a string, continues to work identically. A single string is treated as a one-element list internally.

#### Classless subnet delegation (IPv4 /31 to /25)

If you are using classless subnets in Netbox, you can automatically expand records for the following format zones:

- `<subnet>-<subnet mask bit count>.2.0.192.in-addr.arpa` ([RFC 4183](https://www.rfc-editor.org/rfc/rfc4183.html) style)
- `<subnet>/<subnet mask bit count>.2.0.192.in-addr.arpa` ([RFC 2317](https://www.ietf.org/rfc/rfc2317.html) style)

## Examples

Here is an example configuration for octodns-netbox:

```yaml
providers:
  netbox:
    class: octodns_netbox.NetboxSource

    # Your Netbox URL
    url: https://ipam.example.com

    # Your Netbox Access Token (read-only)
    # This token should have read-only access to Netbox.
    token: env/NETBOX_TOKEN

    # The TTL of the generated records (Optional, default: 60)
    # Time to Live (TTL) specifies the time interval that a DNS record is stored in cache.
    # The default value of 60 is commonly used for dynamic DNS records.
    ttl: 60

    # Advanced Parameters:
    # The following parameters are optional and can be ignored for most use cases.

    # Generate records including subdomains (Optional, default: `true`)
    # If `false`, only records that belong directly to the zone (domain) will be generated.
    # This can be useful to reduce the number of DNS queries and avoid `SubzoneRecordException` errors.
    populate_subdomains: true

    # FQDN field name (Optional, default: `description`)
    # The `dns_name` field on Netbox is provided to hold only a single name,
    # but typically one IP address will correspond to multiple DNS records (FQDNs).
    # The `description` does not have any limitations so by default
    # we use the `description` field to store multiple FQDNs, separated by commas.
    # Other tested values are `dns_name`.
    #
    # Custom fields are also supported by using the `cf_` prefix.
    # For example, if you have a custom field named `additional_dns`,
    # set `field_name: cf_additional_dns`.
    #
    # `field_name` also accepts a list of field names; the source queries every
    # listed field with OR semantics and unions the resulting FQDNs (deduped,
    # order-preserving). The first field is the "primary" — for single-valued
    # PTR records (`multivalue_ptr: false`, the default), only the primary
    # field's FQDNs are considered, falling through to the next field when the
    # primary is empty. List entries may themselves be `cf_*` custom fields,
    # e.g. `field_name: [dns_name, cf_additional_dns]`. See the "Multi-field
    # `field_name`" section above.
    #   field_name: [dns_name, description]
    field_name: description

    # Tag Name (Optional)
    # By default, all records are retrieved from Netbox, but it can be restricted
    # to only IP addresses assigned a specific tag.
    # Multiple values can be passed, resulting in a logical AND operation.
    populate_tags:
      - tag_name

    # VRF ID (Optional)
    # By default, all records are retrieved from Netbox, but it can be restricted
    # to only IP addresses assigned a specific VRF ID.
    # If `0`, it explicitly points to the global VRF.
    populate_vrf_id: 1

    # VRF Name (Optional)
    # VRF can also be specified by name.
    # If there are multiple VRFs with the same name, it would be better to use `populate_vrf_id`.
    # If `Global`, it explicitly points to the global VRF.
    populate_vrf_name: mgmt

    # Multi-value PTR records support (Optional, default: `false`)
    # If `true`, multiple-valued PTR records will be generated.
    # If `false`, the first FQDN value in the field will be used.
    multivalue_ptr: true

  route53:
    class: octodns_route53.Route53Provider
    access_key_id: env/AWS_ACCESS_KEY_ID
    secret_access_key: env/AWS_SECRET_ACCESS_KEY

zones:
  example.com.:
    sources:
      - netbox  # will add A/AAAA records
    targets:
      - route53

  0/26.2.0.192.in-addr.arpa.:
    sources:
      - netbox  # will add PTR records (corresponding to A records)
    targets:
      - route53

  0.8.b.d.0.1.0.0.2.ip6.arpa:
    sources:
      - netbox  # will add PTR records (corresponding to AAAA records)
    targets:
      - route53
```

## Contributing
See [the contributing guide](CONTRIBUTING.md) for detailed instructions on how to get started with our project.

## License
[MIT](https://choosealicense.com/licenses/mit/)
