# Configuration reference

The source reads its settings from its entry under `providers` in the octoDNS config.
octoDNS takes the `class` key and passes every other key to the source.

This config sets the required keys `url` and `token`.
It writes every other key with its default value, except the VRF keys, which have no default.

```yaml
providers:
  netbox:
    class: octodns_netbox.NetboxSource
    url: https://netbox.example.com
    token: env/NETBOX_TOKEN
    field_name: description
    populate_tags: []
    populate_subdomains: true
    multivalue_ptr: false
    ttl: 60
    ssl_verify: true
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

## Keys

| Key | Type | Default | Meaning |
| --- | --- | --- | --- |
| [`url`](#url) | URL | required | The URL of NetBox. |
| [`token`](#token) | string | required | The NetBox API token. |
| [`field_name`](#field_name) | string | `description` | The IP address field that holds the names. |
| [`populate_tags`](#populate_tags) | list of strings | `[]` | Read only the IP addresses that have every one of these tags. |
| [`populate_vrf_id`](#populate_vrf_id) | integer or `"null"` | not set | Read only the IP addresses in the VRF with this ID. |
| [`populate_vrf_name`](#populate_vrf_name) | string | not set | Read only the IP addresses in the VRF with this name. |
| [`populate_subdomains`](#populate_subdomains) | boolean | `true` | Create records for names in subdomains of the zone. |
| [`multivalue_ptr`](#multivalue_ptr) | boolean | `false` | Give a PTR record every name of the IP address, not only the first. |
| [`ttl`](#ttl) | integer | `60` | The TTL of every record, in seconds. |
| [`ssl_verify`](#ssl_verify) | boolean | `true` | Verify the TLS certificate of NetBox. |

octoDNS replaces a value of the form `env/NAME` with the value of the environment variable `NAME`.
The value is a string, and the source converts it to the type of the key: `ttl: env/NETBOX_TTL` with `NETBOX_TTL=120` sets the TTL to 120.
This works for every key except `populate_tags`.
`populate_tags` takes a list, and octoDNS does not replace `env/NAME` inside a list, so write the tags in the config.

### `url`

The URL of NetBox, with the scheme: `https://netbox.example.com`.
The URL can end in `/api` or `/api/`.
The source removes that suffix, because pynetbox adds `/api` itself.

### `token`

The NetBox API token.
The source sends only `GET` requests, so a token without write access is enough.

| Token | Format | Where |
| --- | --- | --- |
| v1 | 40 hexadecimal characters | Every supported NetBox release |
| v2 | `nbt_<key>.<token>` | NetBox 4.5 and later |

Write a v2 token whole, with the `nbt_` prefix.
Every supported pynetbox release, 7.4.1 included, sends both formats to NetBox.

### `field_name`

The field of the NetBox IP address that holds the names.
The source is tested with `description` and `dns_name`.

- `description` holds any number of names, separated by commas.
- `dns_name` holds one name.

A name is an FQDN, with or without the final dot.
The source ignores spaces around commas and empty entries.
It converts each name to the form that octoDNS uses for zone names.
That form is in lower case, and each label that is not ASCII is in IDNA form.
`Höst.Example.com` becomes `xn--hst-sna.example.com.`.
The source lower-cases the whole name, as octoDNS does, and then converts each label on its own.
An ASCII label only becomes lower case, so `höst.Ex_Ample.com` becomes `xn--hst-sna.ex_ample.com.`.
The source skips a name with a label that has no IDNA form, and logs a warning that names it.
In a forward zone, it also skips a name that octoDNS cannot decode, such as `xn--bad_label.example.com`, with the same warning.
See [Names are in the form octoDNS uses](how-it-works.md#names-are-in-the-form-octodns-uses).
Custom fields are not supported.

### `populate_tags`

A list of tag slugs, written as a YAML list:

```yaml
populate_tags:
  - dns
  - external
```

The source reads only the IP addresses that have every tag in the list.
An empty list reads IP addresses with or without tags.
A single string, such as `populate_tags: dns` or `populate_tags: env/NETBOX_TAGS`, is not a list, and the source stops at startup with a pydantic `ValidationError` on `populate_tags`.

### `populate_vrf_id`

The ID of a VRF.
The source reads only the IP addresses in that VRF.

`0` and the string `"null"` select the Global VRF, which holds the IP addresses that have no VRF.
Quote `"null"`.
Unquoted `null` is a YAML null, which leaves the key unset.

When the key is not set, the source reads the IP addresses in every VRF.

### `populate_vrf_name`

The name of a VRF.
At startup, the source asks NetBox for the VRF with this name and uses its ID.

`Global`, with a capital G, selects the Global VRF without a request to NetBox.

The source stops at startup if no VRF or more than one VRF has the name.
Use `populate_vrf_id` when several VRFs share a name.

Do not set both `populate_vrf_id` and `populate_vrf_name`.

### `populate_subdomains`

With `true`, a forward zone gets records for names in its subdomains: `www.lab.example.com` becomes the record `www.lab` in zone `example.com.`.
With `false`, a forward zone gets records only for names one label below the zone and for the zone name itself.

The key has no effect on reverse zones.

### `multivalue_ptr`

With `false`, the PTR record of an IP address gets the first name in the name field.
With `true`, it gets every name in the name field.

When several NetBox IP addresses have the same address, the PTR record gets values from each of them.
See [Create PTR records](reverse-zones.md#fix-a-ptr-record-with-values-from-two-vrfs).

### `ttl`

The TTL, in seconds, of every record that the source creates.

### `ssl_verify`

With `false`, the source does not verify the TLS certificate of NetBox, even when the environment variable `REQUESTS_CA_BUNDLE` or `CURL_CA_BUNDLE` names a CA bundle.
With `true`, the source verifies the certificate against that CA bundle when one of the variables is set, and against the CA bundle of certifi otherwise.

## Unknown keys

The source ignores a key that is not in this reference and logs one warning for it:

```text
Unknown setting populate_tag has no effect.
```

The source still starts.
A misspelled key therefore has no effect.
In this example, the source reads every IP address instead of the tagged ones.

## Errors at startup

octoDNS stops loading the config when the source raises one of these errors.

| Cause | Error |
| --- | --- |
| `url` or `token` is missing | pydantic `ValidationError` that names the key |
| A value has the wrong type, or `url` has no scheme | pydantic `ValidationError` that names the key |
| Both VRF keys are set | `Do not set both populate_vrf_id and populate_vrf_name.` |
| No VRF, or more than one VRF, has the name in `populate_vrf_name` | `Failed to retrieve VRF information by name '<name>'. Use a valid populate_vrf_id instead.` |

A `ValidationError` from the source holds none of the values in the config.
It names the key, so octoDNS prints neither the token nor the value that failed.

## Errors while reading a zone

The source raises `ValueError` when it cannot read a reverse zone name.
It raises the error before it sends a request to NetBox.
An IPv4 zone has one to four octets, and the zone with four octets, such as `1.2.0.192.in-addr.arpa.`, holds the PTR record of one address.
Python's `ipaddress` module raises the `AddressValueError` errors, a kind of `ValueError`.

| Zone name | Error |
| --- | --- |
| The first label before `.in-addr.arpa.` is not an octet, or an octet and a prefix length from 25 to 31, such as `300.1.in-addr.arpa.` or `0/32.2.0.192.in-addr.arpa.` | `Failed to parse the leftmost IPv4 label '<label>' in zone '<zone>' as an octet or slash-based netmask.` |
| Another label before `.in-addr.arpa.` is not an octet, such as `300` in `1.300.in-addr.arpa.` | `AddressValueError: Octet 300 (> 255) not permitted in '300.1.0.0'` |
| More than four labels before `.in-addr.arpa.`, such as `5.4.3.2.1.in-addr.arpa.` | `AddressValueError: Expected 4 octets in '1.2.3.4.5'` |
| A classless zone that does not start at the first address of its network, such as `1/26.2.0.192.in-addr.arpa.` | `ValueError: 192.0.2.1/26 has host bits set` |
| A label before `.ip6.arpa.` is not one hexadecimal digit | `Invalid reverse zone '<zone>'. Each label before '.ip6.arpa.' is one nibble, so '<label>' must be one hex digit.` |

## Python API

Most users run the source from octoDNS commands and need nothing in this section.

`octodns_netbox.NetboxSource(id, /, **settings)` takes the name of the source as its first argument, and the same keys as the config as keyword arguments.
Pass the name positionally.
A keyword argument named `id` goes to the settings, where it is an unknown key, as in the config.
`NetboxSource(id="my-id", url=..., token=...)` worked in 0.5.0, and now raises `TypeError: NetboxSource.__init__() missing 1 required positional argument: 'id'`.
octoDNS passes the name positionally, so configs are not affected.
The source keeps the settings in `source.config`, a frozen `octodns_netbox.NetboxSourceConfig`.

```python
from octodns_netbox import NetboxSource

source = NetboxSource("netbox", url="https://netbox.example.com/api", token="token")
print(source.config.url)  # https://netbox.example.com
print(source.config.ttl)  # 60
```

Version 0.5.0 kept the settings as attributes of the source, such as `source.ttl`.
Read them from `source.config` instead.
