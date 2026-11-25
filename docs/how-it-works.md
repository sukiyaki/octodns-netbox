# How the source maps NetBox IP addresses to records

octoDNS asks the source for the records of one zone at a time.
For each zone, the source queries `/api/ipam/ip-addresses/` in NetBox, reads the names on the IP addresses that come back, and builds A, AAAA, or PTR records.
It keeps nothing between zones, so each zone costs its own query.

This page explains what the source asks NetBox, how it turns the answer into records, and why it works this way.
For the settings, see the [configuration reference](configuration.md).

## The queries

These are the query strings that the source sends, taken from the requests that the tests record against NetBox 4.7.
The table shows them URL-decoded.
`description` is the default `field_name`.
With `field_name: dns_name`, the source sends `dns_name__ic` and `dns_name__empty` instead.

| Zone or setting | Query string |
| --- | --- |
| Forward zone `example.com.` | `description__ic=example.com` |
| IPv4 reverse zone `2.0.192.in-addr.arpa.` | `description__empty=false&parent=192.0.2.0/24&family=4` |
| Classless zone `0/26.2.0.192.in-addr.arpa.` | `description__empty=false&parent=192.0.2.0/26&family=4` |
| IPv6 reverse zone `0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.` | `description__empty=false&parent=2001:db8::/64&family=6` |
| `populate_vrf_id: 1` | adds `vrf_id=1` |
| `populate_vrf_id: 0` or `populate_vrf_name: Global` | adds `vrf_id=null` |
| `populate_tags: [dns, external]` | adds `tag=dns&tag=external` |

pynetbox adds `limit=0` to each query.
When NetBox returns one page of a longer list, pynetbox asks for the rest, so the source reads every IP address.
For a zone with 2,000 IP addresses, the live tests record two requests.

`populate_vrf_name` costs one more request, once, when the source starts: `GET /api/ipam/vrfs/?name=mgmt`.
The source then sends `vrf_id` with the ID that NetBox returned.
`Global` needs no request, because the Global VRF has no ID.

Every filter goes to NetBox in the same query.
NetBox combines them with AND, so `populate_tags: [dns, external]` reads only the IP addresses that have both tags.

## Forward zones

### NetBox returns more IP addresses than the zone needs

The `description` field holds a comma-separated list of names, so the zone name can appear anywhere in it.
NetBox has no filter for "one of the names in this list ends with the zone name".
The source therefore asks for every IP address whose field contains the zone name, without regard to case.
That is the `__ic` filter.

The answer includes IP addresses that do not belong to the zone.
For zone `test.example.com.`, NetBox also returns an IP address named `a-test.example.com`, because that name contains `test.example.com`.

The source checks each name itself.
It keeps a name only when the name is the zone name, or ends with a dot followed by the zone name.
`host.test.example.com` stays in zone `test.example.com.`, and `a-test.example.com` does not.
With `populate_subdomains: false`, it also drops a name that has more than one label in front of the zone name.

### Names are in the form octoDNS uses

DNS compares names without regard to case (RFC 4343).
octoDNS keeps zone and record names in lower case, and writes each label that is not ASCII in IDNA form (RFC 5891): `café` is `xn--caf-dma`.
The source writes each name the same way before the check, so it compares a name and the zone as octoDNS does.
An IP address with the description `Host1.Example.TEST` gets the record `host1` in zone `example.test.`, and its PTR record points to `host1.example.test.`.

The source converts each label on its own, as octoDNS 1.13 and later do.
IDNA does not allow `_`, and octoDNS 1.10 to 1.12 convert the whole name, so they cannot convert `höst.ex_ample.com`.
Label by label, the name becomes `xn--hst-sna.ex_ample.com.` with every supported octoDNS release.

Before it splits a name into labels, the source lower-cases the whole name, as every octoDNS release does.
The lower case of a Greek capital sigma depends on the letters around it.
Python's `str.lower()` turns `Σ` after a letter into `σ` when a letter comes next, and into the final sigma `ς` when none does.
A dot does not count as the next character, so `ΑΣ.α.example.com` becomes `ασ.α.example.com`, which is `xn--mxa0b.xn--mxa.example.com.`.
The label `ΑΣ` on its own would become `ας`, which is `xn--mxa8a`.
Each name gets one form, the form that octoDNS gives the whole name, so the PTR record points to the name of the A record.

In zone `café.example.`, the descriptions `höst.XN--CAF-DMA.EXAMPLE` and `xn--hst-sna.xn--caf-dma.example` are the same name.
Both IP addresses become values of one A record, `xn--hst-sna`, which a YAML file shows as `höst`.

The query holds the zone name in IDNA form, `description__ic=xn--caf-dma.example`.
NetBox returns an IP address only when its field holds that spelling, in any case.
An IP address whose only name is `höst.café.example` does not come back, and gets no record in zone `café.example.`.

NetBox returns the whole field of each IP address that matches, and the source converts every name in it.
When one description holds `höst.café.example, www.xn--caf-dma.example`, the second name makes NetBox return the IP address.
Both names then get records in zone `café.example.`: `xn--hst-sna` and `www`.

Some labels have no IDNA form, such as a label with a zero width joiner (U+200D) between two Latin letters.
The source skips such a name and logs a warning that names the IP address.
The other names in the zone still get their records:

```text
Skipping the name 'a\u200db.xn--caf-dma.example.' of 203.0.113.4 in zone xn--caf-dma.example.: Joiner U+200D not allowed at position 2 in 'a\u200db'
```

octoDNS also decodes each record name back to Unicode for its logs.
A label that starts with `xn--` but is not valid IDNA, such as `xn--bad_label`, has no Unicode form.
octoDNS then stops with `IdnaError: Invalid A-label`, and the zone gets no records, in lenient mode too.
The source therefore skips a name in a forward zone when octoDNS cannot decode its record name, with the same warning:

```text
Skipping the name 'xn--bad_label.a-label.example.' of 192.0.9.2 in zone a-label.example.: Invalid A-label
```

octoDNS 1.10 to 1.12 decode a whole record name when one label starts with `xn--`, and IDNA does not allow `_`.
With those releases, the source also skips `_srv.h\u00f6st.example.com` in zone `example.com.`, because octoDNS cannot decode `_srv.xn--hst-sna`.
octoDNS 1.13 and later decode each label, and the name gets its record.

octoDNS does not decode a PTR value, so the source keeps such a name there, as 0.5.0 did.
The PTR record of `192.0.9.2` points to `xn--bad_label.a-label.example.`.

### octoDNS makes each name relative

The source gives octoDNS each name as an FQDN, and octoDNS makes it relative to the zone.
In zone `example.net.`, the name `web-example-net.example.net` becomes the record `web-example-net`.

## Names that octoDNS rejects

NetBox accepts any text in a description, and people write notes there, such as `Reserved for new printer`.
octoDNS validates each record that the source gives it.
One record that fails stops the zone, and `octodns-sync` then writes none of the zones in the run.

The source therefore checks each name on its own.
It builds the record of one name and one address with the same octoDNS call that builds the zone, and without lenient.
When octoDNS rejects that record, the source skips the name for that address and logs octoDNS's reason:

```text
Skipping the name 'reserved for new printer.' of 192.0.17.2 in zone 17.0.192.in-addr.arpa.: PTR value "reserved for new printer." is not a valid FQDN, via: targets-value-rfc
```

In a forward zone, octoDNS checks the record name, and in a reverse zone, the PTR value.
The other names of the IP address, and the other IP addresses with the same name, still get their records.
The source adds no rule to the rules of octoDNS.
A name that octoDNS accepts, such as the wildcard `*.example.com` or `_srv.example.com`, gets its record.
octoDNS releases word their reasons in other ways, and do not all reject the same names.
octoDNS 1.22 accepts the PTR value `{rack}.example.test.`, and octoDNS 1.10 rejects it.
The source follows the octoDNS release that runs it, so with octoDNS 1.10 it skips that name with the warning above.

With `lenient: true` on the zone, octoDNS keeps a record that fails its validation and logs a warning.
The source then keeps the name too, as 0.5.0 did.

octoDNS 1.10 to 1.12 decode the whole name of such a record for the warning, and for the error without lenient.
In a zone with a label in IDNA form, such as `café.example.`, IDNA can then reject the name too, as it rejects `bad name.café.example`.
Whether IDNA rejects a name that is only too long depends on the release of the idna package.
When IDNA rejects the name, octoDNS stops with an `IdnaError`, in lenient mode too, and the zone gets no records.
The source skips each name for which octoDNS raises an `IdnaError`, in both modes, with the reason that IDNA gives:

```text
Skipping the name 'bad name.xn--caf-dma.example.' of 203.0.113.4 in zone xn--caf-dma.example.: Codepoint U+0020 at position 4 of 'bad name' not allowed
```

## Reverse zones

### The zone name gives the network

The source reads the network from the labels of the zone name.
`2.0.192.in-addr.arpa.` is `192.0.2.0/24`.
`0/26.2.0.192.in-addr.arpa.` and `0-26.2.0.192.in-addr.arpa.` are both `192.0.2.0/26`.
`0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.` is `2001:db8::/64`.

It then asks NetBox for the IP addresses inside that network that have a name.
The `parent` filter compares the address and ignores the mask that NetBox stores with it.

### The PTR name is the reverse pointer of the address

In a zone on octet boundaries, and in an IPv6 zone, the PTR record of an address is the reverse pointer of the address.
For `192.0.2.1`, that is `1.2.0.192.in-addr.arpa.`.

In a classless zone, the reverse pointer is outside the zone.
`1.2.0.192.in-addr.arpa.` is in the parent zone `2.0.192.in-addr.arpa.`, not in `0/26.2.0.192.in-addr.arpa.`.
RFC 2317 delegates part of a `/24` with one CNAME record for each address in the parent zone:

```text
1.2.0.192.in-addr.arpa.  CNAME  1.0/26.2.0.192.in-addr.arpa.
```

The PTR record lives at the target of that CNAME.
The source names it as the example in RFC 2317 does, with the last octet of the address in front of the zone name.
The CNAME records belong to the parent zone, and the source does not create them.

### The PTR value is the first name

An IP address can have several names.
With `multivalue_ptr: false`, the source treats the first name in the field as the main name and uses only that one.
With `multivalue_ptr: true`, it uses every name.

## Records from several IP addresses

The source groups the values by record name and type.
Two IP addresses with the same name give one A record with two values.
When two IP addresses give a record the same value, such as one address with one name in two VRFs, the record gets that value once.
octoDNS would otherwise keep the value twice, and plan an update on every sync against a provider that holds it once.

The same grouping applies to PTR records.
NetBox can hold the same address more than once, for example once in each VRF.
Without a VRF filter, the source reads each of them, and the PTR record of the address gets the value of each.
`multivalue_ptr: false` limits the names of each IP address, not the values of each PTR record.

The source does not pick one of the values.
`multivalue_ptr: false` meant "the first name of each IP address" in 0.5.0 too, and the project keeps every distinct value that a 0.5.0 config gives.
Picking one value would drop the others.
The source logs a warning instead, and the warning names the VRF keys that read one VRF.
It logs the warning only when each VRF gives the PTR record one name, and the VRFs give different names.
Any one VRF then gives the record one value.
When every VRF gives the same name, the PTR record points to that name whichever VRF the source reads.

NetBox holds an address twice in one VRF when the VRF does not enforce uniqueness.
It also holds the address twice in a VRF that enforces uniqueness, when each IP address with that address has a role that NetBox exempts.
`IPAddress.clean()` in `netbox/ipam/models/ip.py` exempts the roles anycast, VIP, VRRP, HSRP, GLBP, and CARP, in NetBox 4.0 and 4.7.
Two anycast IP addresses can therefore share an address in the Global VRF, which enforces uniqueness by default.
The PTR record then gets the value of each row, and the source logs no warning.
No setting of the source picks one of those rows, so the warning could only ask you to change data that NetBox was set up to allow.

The source also logs no warning when one VRF gives the PTR record two names and other VRFs hold the address too.
`192.0.10.1` has the same two names in the Global VRF and in VRF `anycast`, so each VRF alone still gives its PTR record two values.
The source gives the advice to read one VRF only when any VRF you pick gives the record one value.

## Errors instead of empty zones

When the source cannot read a reverse zone name, it raises an error and sends no query.
For example, `00.ip6.arpa.` has a label of two digits, and no rule gives a PTR name for its addresses.
`in-addr.arpa.` and `ip6.arpa.` have no address labels, so they name no network.
The source treats them as reverse zones, so it raises the error and sends no forward query for them.

The source does not return an empty zone in that case.
octoDNS compares the records of the source with the records of the target, and an empty zone would make it plan to delete every record in the target.

## Unknown keys give a warning

The source logs a warning for a config key it does not know, and ignores the key.
Version 0.5.0 accepted any key without a message, so an error would stop configs that work today.
A later major release may turn the warning into an error.

## The source supports both octoDNS record APIs

octoDNS 1.22 added `Rrset` and `Record.from_rrsets`, and deprecated `Rr` and `Record.from_rrs`.
octoDNS 2.0 will remove the old pair.
The source uses the new pair when octoDNS has it, and the old pair otherwise, so it supports octoDNS 1.10 and later without deprecation warnings.
Both paths give octoDNS the same names and values, and the zones are the same.
