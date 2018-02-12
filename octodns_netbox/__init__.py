'''
A NetBox source for octoDNS.

Automatically creating A/AAAA records and their corresponding PTR records
based on a NetBox API.
'''

from collections import defaultdict
from requests import Session
from ipaddress import IPv4Interface, IPv6Interface
from fqdn import FQDN
import logging

try:
    from urllib.parse import quote_plus
except ImportError:
    from urllib import quote_plus

from octodns.record import Record
from octodns.source.base import BaseSource

__VERSION__ = 0.1

class NetboxClientException(Exception):
    pass


class NetboxClientNotFound(NetboxClientException):

    def __init__(self):
        super(NetboxClientNotFound, self).__init__('Not found')


class NetboxClientUnauthorized(NetboxClientException):

    def __init__(self):
        super(NetboxClientUnauthorized, self).__init__('Unauthorized')


class NetboxClient(object):
    def __init__(self, url, token):
        self.url = url
        sess = Session()
        sess.headers.update({'Authorization': 'Token {}'.format(token)})
        self._sess = sess

    def _request(self, method, path, params=None, data=None):
        url = '{}{}'.format(self.url, path)
        resp = self._sess.request(method, url, params=params, json=data)
        if resp.status_code == 401:
            raise NetboxClientUnauthorized()
        if resp.status_code == 404:
            raise NetboxClientNotFound()
        resp.raise_for_status()
        return resp

    def ipaddresses(self, zone_name='', family='', parent=''):
        ret = []

        limit = 50
        offset = 0
        parent = quote_plus(parent) if parent != '' else ''

        while True:
            data = self._request('GET', '/ipam/ip-addresses/?limit={}&offset={}&q={}&family={}&parent={}'
                                    .format(limit, offset, zone_name, family, parent)).json()
            ret += data['results']
            if data['next'] == None:
                break
            offset += limit

        return ret


class NetboxSource(BaseSource):
    '''
    Netbox source using API

    netbox:
        class: octodns_netbox.NetboxSource
        # Your API Root URL (required)
        url: http://localhost:8000/api/
        # API v2 account access token (required)
        token: letmein
    '''
    SUPPORTS_GEO = False
    SUPPORTS = set(('A', 'AAAA', 'PTR'))

    def __init__(self, id, url, token, ttl=60):
        self.log = logging.getLogger('NetboxSource[{}]'.format(id))
        self.log.debug('__init__: id=%s, url=%s, token=***', id, url)
        super(NetboxSource, self).__init__(id)
        self._client = NetboxClient(url, token)
        self.ttl = ttl

        self._ipam_records = []

    def ipam_records(self, zone=None, family=None, parent=None):
        try:
            if zone != None:
                self._ipam_records = \
                    self._client.ipaddresses(zone_name=zone.name[:-1])
            elif parent != None:
                self._ipam_records = \
                    self._client.ipaddresses(parent=parent, family=family)
            else:
                return []

        except NetboxClientNotFound:
            return []

        return self._ipam_records

    def populate(self, zone, target=False, lenient=False):
        self.log.debug('populate: name=%s, target=%s, lenient=%s', zone.name,
                       target, lenient)
        before = len(zone.records)

        if zone.name.endswith('.in-addr.arpa.'):
            self._populate_PTRv4(zone, lenient)
        elif zone.name.endswith('.ip6.arpa.'):
            self._populate_PTRv6(zone, lenient)
        else:
            self._populate_normal(zone, lenient)

        self.log.info('populate:   found %s records',
            len(zone.records) - before)

    def _populate_PTRv4(self, zone, lenient):
        zone_length = len(zone.name.split('.')[:-3])

        if zone_length > 3:
            # parent = networkaddr/mask
            parent = '.'.join(zone.name.split('.')[:-3][::-1])
        else:
            # parent = networkaddr
            parent = '.'.join(zone.name.split('.')[:-3][::-1])
            for i in range(4 - zone_length):
                parent += '.0'
            parent += '/{}'.format(8 * zone_length)

        for ipam_record in self.ipam_records(parent=parent, family=4):
            ip_address = IPv4Interface(ipam_record['address']).ip
            description = ipam_record['description']

            if zone_length > 3:
                _name = '{}.{}'.format(ip_address.exploded.split('.')[-1], zone.name)
                name = zone.hostname_from_fqdn(_name)
            else:
                name = zone.hostname_from_fqdn(ip_address.reverse_pointer)

            # take the first fqdn
            for _fqdn in description.split(','):
                fqdn = FQDN(_fqdn)
                if fqdn.is_valid:
                    value = fqdn.absolute
                    break

            record = Record.new(zone, name, {
                    'ttl': self.ttl,
                    'type': 'PTR',
                    'value': value
            }, source=self, lenient=lenient)
            zone.add_record(record)

    def _populate_PTRv6(self, zone, lenient):
        zone_length = len(zone.name.split('.')[:-3])

        zone_reverse_str = ''.join(zone.name.split('.')[:-3][::-1])
        if len(zone_reverse_str) % 4 != 0:
            for i in range(4 - (len(zone_reverse_str) % 4)):
                zone_reverse_str += '0'
        parent = ':'.join([zone_reverse_str[i: i+4] for i in range(0, len(zone_reverse_str), 4)])
        parent += '::/{}'.format(zone_length * 4)

        for ipam_record in self.ipam_records(parent=parent, family=6):
            ip_address = IPv6Interface(ipam_record['address']).ip
            description = ipam_record['description']

            name = zone.hostname_from_fqdn(ip_address.reverse_pointer)

            # take the first fqdn
            for _fqdn in description.split(','):
                fqdn = FQDN(_fqdn)
                if fqdn.is_valid:
                    value = fqdn.absolute
                    break

            record = Record.new(zone, name, {
                    'ttl': self.ttl,
                    'type': 'PTR',
                    'value': value
            }, source=self, lenient=lenient)
            zone.add_record(record)

    def _populate_normal(self, zone, lenient):
        data = defaultdict(lambda: defaultdict(list))

        for ipam_record in self.ipam_records(zone):
            ip_address = ipam_record['address'].split('/')[0]
            description = ipam_record['description']
            family = ipam_record['family']

            for _fqdn in description.split(','):
                fqdn = FQDN(_fqdn)
                if not fqdn.is_valid:
                    continue

                if fqdn.absolute.endswith(zone.name):
                    name = zone.hostname_from_fqdn(fqdn.absolute)
                    _type = 'A' if family == 4 else 'AAAA'

                    data[name][_type].append(ip_address)

        for name, types in data.items():
            for _type, d in types.items():
                record = Record.new(zone, name, {
                    'ttl': self.ttl,
                    'type': _type,
                    'values': d
                }, source=self, lenient=lenient)
                try:
                    zone.add_record(record)
                except SubzoneRecordException:
                    self.log.debug('_populate_normal: skipping subzone '
                                   'record=%s', record)
