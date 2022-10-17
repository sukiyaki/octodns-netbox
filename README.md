#  A [NetBox](https://github.com/digitalocean/netbox) source for [octoDNS](https://github.com/github/octodns/)

[![PyPI](https://img.shields.io/pypi/v/octodns-netbox)](https://pypi.python.org/pypi/octodns-netbox)
[![PyPI - Python Version](https://img.shields.io/pypi/pyversions/octodns-netbox)](https://pypi.python.org/pypi/octodns-netbox)
[![PyPI - License](https://img.shields.io/pypi/l/octodns-netbox)](LICENSE)
[![Code Climate coverage](https://img.shields.io/codeclimate/coverage/sukiyaki/octodns-netbox)](https://codeclimate.com/github/sukiyaki/octodns-netbox)
[![Code Climate maintainability](https://img.shields.io/codeclimate/maintainability/sukiyaki/octodns-netbox)](https://codeclimate.com/github/sukiyaki/octodns-netbox)

You can have complete control over your DNS records with Netbox!

⚠️ This is a **source** for octoDNS! We can only serve to populate records into a zone, cannot be synced **to** Netbox.

## Getting started

### A records / AAAA records

This source retrieves IP address information from Netbox and creates A/AAAA records for octoDNS. For this purpose, it is essential to manage the mapping between IP addresses and FQDNs in Netbox. We use a `description` field as a comma-separated list of hostnames (FQDNs).

#### 🚨 `dns_name` field
Starting with [Netbox v2.6.0](https://github.com/netbox-community/netbox/issues/166), IPAddress now has a `dns_name` field. But we **do not** use this field by default because this `dns_name` field can only store **single** FQDN. To use a `dns_name` field, set `field_name: dns_name` in [the configuration](#example-configuration).

#### 🔍 Example
- IP Address: `192.0.2.1/24`
  - Description: `en0.host1.example.com,host1.example.com`
- DNS Zone: `example.com.`
  - `en0.host1. A 192.0.2.1`
  - `host1. A 192.0.2.1`

### PTR records

PTR records supported as well. OctoDNS [supports Multiple PTR records on a single IP](https://github.com/octodns/octodns/pull/754), but it is not ot used much in productions. By default, `multivalue_ptr: false` is set and the first FQDN in the field will be used to generate the PTR record.

#### 🔍 Example (`multivalue_ptr: false` - default)
- IP Address: `192.0.2.1/24`
  - Description: `en0.host1.example.com,host1.example.com`
- DNS Zone: `2.0.192.in-addr.arpa.`
  - `1. PTR en0.host1.example.com`

#### 🔍 Example (`multivalue_ptr: true`)
- IP Address: `192.0.2.1/24`
  - Description: `en0.host1.example.com,host1.example.com`
- DNS Zone: `2.0.192.in-addr.arpa.`
  - `1. PTR en0.host1.example.com`
  - `1. PTR host1.example.com`

#### Classless subnet delegation (IPv4 /31 to /25)

When creating classless reverse lookup zones, we support two notation as the following ones:

- `<subnet>-<subnet mask bit count>.2.0.192.in-addr.arpa` ([RFC 4183](https://www.rfc-editor.org/rfc/rfc4183.html) alike) or
- `<subnet>/<subnet mask bit count>.2.0.192.in-addr.arpa` ([RFC 2317](https://www.ietf.org/rfc/rfc2317.html) alike)

## Example Configuration

You must configure `url` and `token` to work with the [NetBox API](https://netbox.readthedocs.io/en/latest/api/overview/).

```yaml
providers:
  netbox:
    class: octodns_netbox.NetboxSource
    # Your Netbox URL
    url: https://ipam.example.com
    # Your Netbox Access Token (read-only)
    token: env/NETBOX_TOKEN
    # The TTL of the generated records (Optional, default: 60)
    ttl: 60
    #
    # !!!!! Advanced Parameters !!!!!
    # Just ignore below and no need to write these lines in your yaml.
    #
    # Generate records including subdomains (Optional, default: `true`)
    # If `false`, only records that belong directly to the zone (domain) will be generated.
    # If you are seeing a lot of `SubzoneRecordException` in your logs, change this to `false`.
    populate_subdomains: true
    # FQDN field name (Optional, default: `description`)
    # The `dns_name` field on Netbox is provided to hold only a single name,
    # but typically one IP address will correspond to multiple DNS records (FQDNs).
    # The `description` does not have any limitations so by default
    # we use the `description` field to store multiple FQDNs, separated by commas.
    # Tested: `description`, `dns_name`
    field_name: description
    # Tag Name (Optional)
    # By default, all records are retrieved from Netbox, but it can be restricted
    # to only IP addresses assigned a specific tag.
    populate_tags:
      - tag_name
      - passing multiple values will result in a logical AND operation
    # VRF ID (Optional)
    # By default, all records are retrieved from Netbox, but it can be restricted
    # to only IP addresses assigned a specific VRF ID.
    # If `0`, explicitly points for global VRF.
    populate_vrf_id: 1
    # VRF Name (Optional)
    # VRF can also be specified by name.
    # If there are multiple VRFs with the same name, it would be better to use `populate_vrf_id`.
    # If `Global`, explicitly points for global VRF.
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
