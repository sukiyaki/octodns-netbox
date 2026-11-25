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
| [`ttl`](#ttl) | integer, 0 or more | `60` | The TTL of every record, in seconds. |
| [`ssl_verify`](#ssl_verify) | boolean | `true` | Verify the TLS certificate of NetBox. |

octoDNS replaces a value of the form `env/NAME` with the value of the environment variable `NAME`.
octoDNS turns a value that is a number, such as `120`, into a number, and keeps any other value as a string.
The source converts the value to the type of the key: `ttl: env/NETBOX_TTL` with `NETBOX_TTL=120` sets the TTL to 120.
This works for every key except `populate_tags`.
`populate_tags` takes a list, and octoDNS does not replace `env/NAME` inside a list, so write the tags in the config.

### `url`

The URL of NetBox, with the scheme: `https://netbox.example.com`.
The URL can end in `/api` or `/api/`.
The source removes that suffix, because pynetbox adds `/api` itself.

The URL cannot hold a user name or a password, such as `https://user:pass@netbox.example.com`.
requests would send them in place of the token, and NetBox would refuse each request.
The source stops at startup with a pydantic `ValidationError` on `url`.

### `token`

The NetBox API token.
The source sends only `GET` requests, so a token without write access is enough.

The source authenticates to NetBox with the token alone.
It ignores `~/.netrc` and the file that the environment variable `NETRC` names.
requests would otherwise send a login from that file in place of the token.
The source still uses the proxy settings in the environment, such as `HTTPS_PROXY`, and the CA bundle in `REQUESTS_CA_BUNDLE` or `CURL_CA_BUNDLE`.
When NetBox redirects a request to another host, the source sends the redirected request without the token, as requests does.

The log messages of the source hold neither the token nor the URL, at any log level.
At the DEBUG level, urllib3 logs the host, the path, and the query string of each request that the source sends.

| Token | Format | Where |
| --- | --- | --- |
| v1 | 40 hexadecimal characters | Every supported NetBox release |
| v2 | `nbt_<key>.<token>` | NetBox 4.5 and later |

Write a v2 token whole, with the `nbt_` prefix.
Every supported pynetbox release, 7.4.1 included, sends both formats to NetBox.

The source removes the whitespace around the token, such as the line break at the end of a Kubernetes Secret, or the carriage return that a `.env` file with CRLF line ends leaves at the end of each value.
A token that still holds whitespace, a character that is not printable, such as a control character, or a character that is not ASCII, such as `é`, stops the source at startup with a pydantic `ValidationError` on `token`.

A v1 token is hexadecimal, so some v1 tokens hold only digits.
octoDNS turns such an `env/` value into a number, which loses the zeros at its start.
The source writes the number back with 40 digits, the length of a v1 token, so the token is the same.

Put quotes around a token that you write in the config itself, such as `token: '0123456701234567012345670123456701234567'`.
Without quotes, YAML reads a token of digits that starts with `0` and holds no `8` or `9` as an octal number.
The source would then send other digits, and NetBox would refuse each request.

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
It skips a name with an empty label, such as `.example.com` or `a..example.com`, with the same warning, also when the zone is lenient.
In a forward zone, it also skips a name that octoDNS cannot decode, such as `xn--bad_label.example.com`, with the same warning.
See [Names are in the form octoDNS uses](how-it-works.md#names-are-in-the-form-octodns-uses).

The source also skips a name that octoDNS's validation rejects, with the same warning and the reason that octoDNS gives.
In a forward zone, octoDNS checks the record name, such as `see wiki` in `see wiki.example.com`, a label longer than 63 characters, or `@`.
In a reverse zone, octoDNS checks the PTR value, such as free text like `Reserved for new printer`, a name with one label like `gateway`, or `*`.
The other names of the IP address, and the other IP addresses, still get their records.
With `lenient: true` on the zone in the octoDNS config, octoDNS keeps such a record and logs a warning, and the source keeps the name.
In a zone with a label in IDNA form, such as `café.example.`, octoDNS 1.10 to 1.12 can raise an `IdnaError` for such a name, in lenient mode too, and the source then skips the name in both modes.
See [Names that octoDNS rejects](how-it-works.md#names-that-octodns-rejects).
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

Each slug must be the slug of a tag in NetBox, in the same case.
For a slug that no tag has, NetBox answers `400 Bad Request`, and the zone stops with an error from pynetbox.
NetBox 4.7 gives this error for `populate_tags: [no-such-tag]`:

```text
RequestError: The request failed with code 400 Bad Request: {'tag': ['Select a valid choice. no-such-tag is not one of the available choices.']}
```

### `populate_vrf_id`

The ID of a VRF.
The source reads only the IP addresses in that VRF.

`0` and the string `"null"` select the Global VRF, which holds the IP addresses that have no VRF.
Quote `"null"`.
Unquoted `null` is a YAML null, which leaves the key unset.
`true` and `false` are not IDs, and stop the source at startup with a pydantic `ValidationError` on `populate_vrf_id`.

When the key is not set, the source reads the IP addresses in every VRF.

### `populate_vrf_name`

The name of a VRF.
At startup, the source asks NetBox for the VRF with this name and uses its ID.

`Global`, with a capital G, selects the Global VRF without a request to NetBox.

The source stops at startup if no VRF or more than one VRF has the name.
It also stops if the name is empty or holds only whitespace, with a pydantic `ValidationError` on `populate_vrf_name`.
NetBox ignores such a name filter and returns every VRF, so the source would read the only VRF of a NetBox that has one.
Use `populate_vrf_id` when several VRFs share a name.

A VRF named `null` cannot be selected by name.
NetBox reads the filter `name=null` as an empty name, so the source finds no VRF and stops with `Failed to retrieve VRF information by name 'null'`.
Set `populate_vrf_id` to the ID of that VRF instead.

Do not set both `populate_vrf_id` and `populate_vrf_name`.

### `populate_subdomains`

With `true`, a forward zone gets records for names in its subdomains: `www.lab.example.com` becomes the record `www.lab` in zone `example.com.`.
With `false`, a forward zone gets records only for names one label below the zone and for the zone name itself.

The key has no effect on reverse zones.

### `multivalue_ptr`

With `false`, the PTR record of an IP address gets the first name in the name field that the source can use.
A name that the source skips, such as a name without an IDNA form or a PTR value that octoDNS rejects, does not count, and the next name takes its place.
With `true`, it gets every name in the name field that the source can use.

When several NetBox IP addresses have the same address, the PTR record gets values from each of them.
See [Create PTR records](reverse-zones.md#fix-a-ptr-record-with-values-from-two-vrfs).

### `ttl`

The TTL, in seconds, of every record that the source creates.
A negative TTL, `true`, or `false` stops the source at startup with a pydantic `ValidationError` on `ttl`.

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
| `url` holds a user name or a password | pydantic `ValidationError` that names `url` |
| `token` holds whitespace that is not at its start or end, or a character that is not printable or not ASCII | pydantic `ValidationError` that names `token` |
| `ttl` is negative, `ttl` or `populate_vrf_id` is `true` or `false`, or `populate_vrf_name` is empty or holds only whitespace | pydantic `ValidationError` that names the key |
| Both VRF keys are set | `Do not set both populate_vrf_id and populate_vrf_name.` |
| No VRF, or more than one VRF, has the name in `populate_vrf_name` | `Failed to retrieve VRF information by name '<name>'. Use a valid populate_vrf_id instead.` |

A `ValidationError` from the source holds none of the values in the config.
It names the key, so octoDNS prints neither the token nor the value that failed.

## Errors while reading a zone

When NetBox refuses the query of a zone, the zone stops with pynetbox's `RequestError`.
A slug in `populate_tags` that no tag has gives this error, as [`populate_tags`](#populate_tags) shows.

The source raises `ValueError` when it cannot read a reverse zone name.
It raises the error before it sends a request to NetBox.
An IPv4 zone has one to four octets, and the zone with four octets, such as `1.2.0.192.in-addr.arpa.`, holds the PTR record of one address.
Python's `ipaddress` module raises the `AddressValueError` errors, a kind of `ValueError`.

| Zone name | Error |
| --- | --- |
| `in-addr.arpa.` or `ip6.arpa.`, with no labels in front | `Invalid reverse zone '<zone>'. It has no address labels, so it names no network.` |
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
