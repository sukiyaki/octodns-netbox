# octodns-netbox

[![PyPI](https://img.shields.io/pypi/v/octodns-netbox)](https://pypi.org/project/octodns-netbox/)
[![Python versions](https://img.shields.io/pypi/pyversions/octodns-netbox)](https://pypi.org/project/octodns-netbox/)
[![License](https://img.shields.io/pypi/l/octodns-netbox)](https://github.com/sukiyaki/octodns-netbox/blob/main/LICENSE)

octodns-netbox is a source for [octoDNS](https://github.com/octodns/octodns) that reads IP addresses from [NetBox](https://github.com/netbox-community/netbox).
It creates A and AAAA records from the names you store on each IP address, and PTR records for your reverse zones.

It is a source, not a provider.
octoDNS reads records from it and writes them to the DNS providers you configure as targets.
The source cannot be a target, and it never writes to NetBox.

## What it does

- It reads the IP addresses in NetBox IPAM.
  Each IP address holds its names in the `description` field as a comma-separated list, or one name in the `dns_name` field.
- It creates an A record for each IPv4 address and an AAAA record for each IPv6 address whose name is in a forward zone.
- It creates a PTR record for each IP address in a reverse zone.
  It handles IPv4 zones on octet boundaries, IPv6 nibble zones, and classless IPv4 zones for prefix lengths 25 to 31.
  A classless zone name starts with the last octet of the network and the prefix length, such as `0/26` (the form in RFC 2317) or `0-26` (the form in RFC 4183).
- It can read only the IP addresses in one VRF, or only the IP addresses with given tags.
- It skips a name that octoDNS rejects, such as free text in a description, and logs a warning.
  The other records of the zone are still created.

It creates no other record types.
It reads nothing from NetBox except IP addresses and, when you name a VRF, that VRF.

## Install

```sh
pip install octodns-netbox
```

The package installs octoDNS as a dependency.
Install the octoDNS provider for your DNS service as well.

## Quick start

This example creates the records for zone `example.test.` and its reverse zone `100.51.198.in-addr.arpa.`.
It assumes that NetBox holds these IP addresses:

| IP address | Description |
| --- | --- |
| `198.51.100.1/24` | `Host1.Example.TEST` |
| `198.51.100.2/24` | `Host2.example.test` |

1. In NetBox, create an API token.
   The source sends only `GET` requests, so a token without write access is enough.
2. Put the token in the environment variable `NETBOX_TOKEN`.
   Replace `<token>` with the whole token.
   A v2 token from NetBox 4.5 or later starts with `nbt_`.

   ```sh
   export NETBOX_TOKEN='<token>'
   ```

3. Save this octoDNS config as `config.yaml`.
   Replace `https://netbox.example.com` with the URL of your NetBox.

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
     example.test.:
       sources:
         - netbox
       targets:
         - yaml
     100.51.198.in-addr.arpa.:
       sources:
         - netbox
       targets:
         - yaml
   ```

4. See the changes that octoDNS plans:

   ```sh
   octodns-sync --config-file config.yaml
   ```

   The plan creates two records in each zone.
5. Write the zones:

   ```sh
   octodns-sync --config-file config.yaml --doit
   ```

   octoDNS writes one file per zone to `./zones`.
   The source lower-cases every name, so `Host1.Example.TEST` becomes `host1`:

   ```yaml
   # example.test.yaml
   host1:
     ttl: 60
     type: A
     value: 198.51.100.1
   host2:
     ttl: 60
     type: A
     value: 198.51.100.2
   ```

   ```yaml
   # 100.51.198.in-addr.arpa.yaml
   '1':
     ttl: 60
     type: PTR
     value: host1.example.test.
   '2':
     ttl: 60
     type: PTR
     value: host2.example.test.
   ```

6. Replace the `yaml` target with the octoDNS provider of your DNS service.

## Supported versions

| Component | Supported | Tested in CI |
| --- | --- | --- |
| Python | 3.11 to 3.15 | 3.11, 3.12, 3.13, 3.14, and 3.15 |
| octoDNS | 1.10 or later, before 2.0 | 1.10.0 and the newest release |
| pynetbox | 7.4.1 or later, before 8.0 | 7.4.1 and the newest release |
| NetBox | 4.0 to 4.7 | 4.0 with a v1 token, 4.7 with v1 and v2 tokens, and every week the newest release with a v2 token |

The NetBox tests run octoDNS against a real NetBox in Docker.
Each pull request tests the pinned NetBox releases, each with the locked and the lowest direct dependency versions.
Every week, CI also tests the `latest` image of netbox-docker, and it tests the lowest dependency versions again, because those inputs can change without a commit.
A new NetBox release can fail the weekly run before this table lists that release.
NetBox 4.5 and later v2 API tokens work with every supported pynetbox release, 7.4.1 included.

## Documentation

- [Configuration reference](https://github.com/sukiyaki/octodns-netbox/blob/main/docs/configuration.md) lists every setting, its type, and its default.
- [Create A and AAAA records](https://github.com/sukiyaki/octodns-netbox/blob/main/docs/forward-zones.md) for a forward zone.
- [Create PTR records](https://github.com/sukiyaki/octodns-netbox/blob/main/docs/reverse-zones.md) for IPv4, classless, and IPv6 reverse zones.
- [Read one VRF or tagged IP addresses](https://github.com/sukiyaki/octodns-netbox/blob/main/docs/filter-by-vrf-and-tag.md) only.
- [How the source maps NetBox to records](https://github.com/sukiyaki/octodns-netbox/blob/main/docs/how-it-works.md) explains the queries it sends and the names it builds.

## Changes

[GitHub Releases](https://github.com/sukiyaki/octodns-netbox/releases) lists the changes in each version and the steps to upgrade.

## Contributing

[CONTRIBUTING.md](https://github.com/sukiyaki/octodns-netbox/blob/main/CONTRIBUTING.md) tells you how to set up the project, run the tests, and release a version.

## Security

To report a vulnerability, follow [SECURITY.md](https://github.com/sukiyaki/octodns-netbox/blob/main/SECURITY.md).
Do not open a public issue for it.

## License

[MIT](https://github.com/sukiyaki/octodns-netbox/blob/main/LICENSE)
