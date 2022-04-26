'''
A NetBox source for octoDNS.

Automatically creating A/AAAA records and their corresponding PTR records
based on a NetBox API.
'''

from collections import defaultdict
from requests import Session
from ipaddress import ip_interface
import re
import logging

try:
    from urllib.parse import quote_plus
except ImportError:
    from urllib import quote_plus

from octodns.zone import SubzoneRecordException, Zone
from octodns.record import Record
from octodns.source.base import BaseSource

__VERSION__ = 0.1


# https://stackoverflow.com/a/2532344
def is_valid_hostname(hostname):
    if len(hostname) > 255:
        return False

    try:
        if hostname[-1] == ".":
            hostname = hostname[:-1]
        allowed = re.compile("(?!-)[A-Z\d-]{1,63}(?<!-)$", re.IGNORECASE)
        return all(allowed.match(x) for x in hostname.split("."))
    except:
        return False


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

    def ipaddresses(self, zone_name='', family='', parent='', tag=''):
        ret = []
        # OctoDNS zone_name does not have leading '.', need to add it
        if zone_name:
            zone_name = "."+zone_name
        limit = 50
        offset = 0
        parent = quote_plus(parent) if parent != '' else ''

        while True:
            query=''
            if(tag == ''):
                query='/ipam/ip-addresses/?limit={}&offset={}&q={}&family={}&parent={}'.format(limit, offset, zone_name, family, parent)
            else:
                query='/ipam/ip-addresses/?limit={}&offset={}&q={}&family={}&parent={}&tag={}'.format(limit, offset, zone_name, family, parent, tag)
            data = self._request(
                'GET', query).json()
            if (parent):
                ret += data['results']
            # data may contain records for subdomains underneath zone_name. These entries are excluded.
            else:
                data_well = []
                for element in data['results']:
                    if (element['dns_name'].count('.') > zone_name.count('.')):
                        continue
                    else:
                        data_well.append(element)
                ret += data_well

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
    SUPPORTS_DYNAMIC = False
    SUPPORTS = set(('A', 'AAAA', 'PTR'))

    def __init__(self, id, url, token, tag='', ttl=60):
        self.log = logging.getLogger('NetboxSource[{}]'.format(id))
        self.log.debug('__init__: id=%s, url=%s, token=***', id, url)
        super(NetboxSource, self).__init__(id)
        self._client = NetboxClient(url, token)
        self.ttl = ttl
        self.tag = tag

        self._ipam_records = []

    def ipam_records(self, zone=None, family=None, parent=None):
        try:
            if zone != None:
                self._ipam_records = \
                    self._client.ipaddresses(zone_name=zone.name[:-1], tag=self.tag)
            elif parent != None:
                self._ipam_records = \
                    self._client.ipaddresses(parent=parent, family=family, tag=self.tag)
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

        ipam_records = self.ipam_records(parent=parent, family=4)
        # Iterate over copy of list of ipam records and remove all duplicate addresses while merging dns names
        for ipam_record in list(ipam_records):
            dup_elements = list(filter(lambda x: ipam_record['address'] in x['address'], ipam_records))
            for elem in dup_elements:
                if elem != ipam_record and ipam_record in ipam_records:
                    ipam_record['dns_name'] += ","+elem['dns_name']
                    ipam_records.remove(elem)

        for ipam_record in ipam_records:
            ip_address = ip_interface(ipam_record['address']).ip
            description = ipam_record['dns_name']

            if zone_length > 3:
                _name = '{}.{}'.format(
                    ip_address.compressed.split('.')[-1], zone.name)
                name = zone.hostname_from_fqdn(_name)
            else:
                name = zone.hostname_from_fqdn(ip_address.reverse_pointer)

            # Check if fqdns are valid and if so append them. For validity trailing dot is needed.
            fqdn = []
            for _fqdn in description.split(','):
                _fqdn += "."
                if is_valid_hostname(_fqdn):
                    fqdn.append(_fqdn)
                else:
                    self.log.info('[is_valid_hostname] failed >>%s<<', _fqdn)

            if fqdn:
                # Support for Multi-PTRecords
                if(len(fqdn) == 1):
                    record = Record.new(
                        zone,
                        name, {'ttl': self.ttl,
                               'type': 'PTR',
                               'value': fqdn[0]},
                        source=self,
                        lenient=lenient)
                else:
                    record = Record.new(
                        zone,
                        name, {'ttl': self.ttl,
                               'type': 'PTR',
                               'values': fqdn},
                        source=self,
                        lenient=lenient)
                zone.add_record(record)

    def _populate_PTRv6(self, zone, lenient):
        zone_length = len(zone.name.split('.')[:-3])

        zone_reverse_str = ''.join(zone.name.split('.')[:-3][::-1])
        if len(zone_reverse_str) % 4 != 0:
            for i in range(4 - (len(zone_reverse_str) % 4)):
                zone_reverse_str += '0'
        parent = ':'.join([
            zone_reverse_str[i:i + 4]
            for i in range(0, len(zone_reverse_str), 4)
        ])
        parent += '::/{}'.format(zone_length * 4)

        for ipam_record in self.ipam_records(parent=parent, family=6):
            ip_address = ip_interface(ipam_record['address']).ip
            description = ipam_record['dns_name']

            name = zone.hostname_from_fqdn(ip_address.reverse_pointer)

            # take the first fqdn
            fqdn = None
            for _fqdn in description.split(','):
                if is_valid_hostname(_fqdn):
                    fqdn = '{}.'.format(_fqdn)
                    break
                else:
                    self.log.info('[is_valid_hostname] failed >>%s<<', _fqdn)

            if fqdn:
                record = Record.new(
                    zone,
                    name, {'ttl': self.ttl,
                           'type': 'PTR',
                           'value': fqdn},
                    source=self,
                    lenient=lenient)
                zone.add_record(record)

    def _populate_normal(self, zone, lenient):
        data = defaultdict(lambda: defaultdict(list))

        for ipam_record in self.ipam_records(zone):
            ip_address = ip_interface(ipam_record['address']).ip
            description = ipam_record['dns_name']

            for _fqdn in description.split(','):
                if is_valid_hostname(_fqdn):
                    fqdn = '{}.'.format(_fqdn)

                    if fqdn.endswith(zone.name):
                        name = zone.hostname_from_fqdn(fqdn)
                        _type = 'A' if ip_address.version == 4 else 'AAAA'

                        data[name][_type].append(ip_address.compressed)
                else:
                    self.log.info('[is_valid_hostname] failed >>%s<<', _fqdn)

        for name, types in data.items():
            for _type, d in types.items():
                record = Record.new(
                    zone,
                    name, {'ttl': self.ttl,
                           'type': _type,
                           'values': d},
                    source=self,
                    lenient=lenient)
                try:
                    zone.add_record(record)
                except SubzoneRecordException:
                    self.log.debug('_populate_normal: skipping subzone '
                                   'record=%s', record)
