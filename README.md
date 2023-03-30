#  A [NetBox](https://github.com/digitalocean/netbox) source for [octoDNS](https://github.com/github/octodns/)

[![PyPI](https://img.shields.io/pypi/v/octodns-netbox)](https://pypi.python.org/pypi/octodns-netbox)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/octodns-netbox)](https://pypi.python.org/pypi/octodns-netbox)
[![PyPI - License](https://img.shields.io/pypi/l/octodns-netbox)](LICENSE)
[![Code Climate coverage](https://img.shields.io/codeclimate/coverage/sukiyaki/octodns-netbox)](https://codeclimate.com/github/sukiyaki/octodns-netbox)
[![Code Climate maintainability](https://img.shields.io/codeclimate/maintainability/sukiyaki/octodns-netbox)](https://codeclimate.com/github/sukiyaki/octodns-netbox)

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

### PTR records

`octodns-netbox` also supports PTR records. By default, only the first FQDN in the field is used to generate the PTR record, but you can enable multiple PTR records for a single IP by setting the `multivalue_ptr` parameter to `true` in [the configuration](#examples).

#### 🔍 Example (`multivalue_ptr: false` - default)
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
