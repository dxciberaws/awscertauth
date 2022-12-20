import logging
import os

from io import BytesIO

from OpenSSL import crypto
from OpenSSL.SSL import FILETYPE_PEM

import random

import ipaddress
import tldextract

from argparse import ArgumentParser

from collections import OrderedDict

import threading

import boto3
import shlex
import string
import re
import datetime

# =================================================================
# Valid for 3 years from now
# Max validity is 39 months:
# https://casecurity.org/2015/02/19/ssl-certificate-validity-periods-limited-to-39-months-starting-in-april/
CERT_NOT_AFTER = 3 * 365 * 24 * 60 * 60

CERTS_DIR = './ca/certs/'

CERT_NAME = 'DXC AWS LZ CA'
SSM_PREFIX = '/CA/'

DEF_HASH_FUNC = 'sha256'

ROOT_CA = 'root_ca'


# =================================================================
class CertificateAuthority(object):
    """
    Utility class for signing individual certificate
    with a root cert.

    Static generate_ca_root() method for creating the root cert

    All certs saved on filesystem. Individual certs are stored
    in specified certs_dir and reused if previously created.
    """

    def __init__(self, ca_name,
                 ca_file_cache,
                 cert_cache=None,
                 cert_not_before=0,
                 cert_not_after=CERT_NOT_AFTER,
                 overwrite=False):

        if isinstance(ca_file_cache, str):
            self.ca_file_cache = RootCACache(ca_file_cache)
        else:
            self.ca_file_cache = ca_file_cache

        if isinstance(cert_cache, str):
            self.cert_cache = FileCache(cert_cache)
        elif isinstance(cert_cache, int):
            self.cert_cache = LRUCache(max_size=cert_cache)
        elif cert_cache is None:
            self.cert_cache = LRUCache(max_size=100)
        else:
            self.cert_cache = cert_cache

        self.ca_name = ca_name

        self.cert_not_before = cert_not_before
        self.cert_not_after = cert_not_after

        res = self.load_root_ca_cert(overwrite=overwrite)
        self.ca_cert, self.ca_key = res
        
    def load_root_ca_cert(self, overwrite=False):
        cert_str = None

        if not overwrite:
            cert_str = self.ca_file_cache.get(ROOT_CA)

        # if cached, just read pem
        if cert_str:
            cert, key = self.read_pem(BytesIO(cert_str))
        else:
            cert, key = self.generate_ca_root(self.ca_name)

            # Write cert + key
            buff = BytesIO()
            self.write_pem(buff, cert, key)
            cert_str = buff.getvalue()

            # store cert in cache
            self.ca_file_cache[ROOT_CA] = cert_str

        return cert, key

    def is_host_ip(self, host):
        try:
            # if py2.7, need to decode to unicode str
            if hasattr(host, 'decode'):  #pragma: no cover
                host = host.decode('ascii')

            ipaddress.ip_address(host)
            return True
        except (ValueError, UnicodeDecodeError):
            return False

    def get_wildcard_domain(self, host):
        host_parts = host.split('.', 1)
        if len(host_parts) < 2 or '.' not in host_parts[1]:
            return host

        ext = tldextract.extract(host)

        # allow using parent domain if:
        # 1) no suffix (unknown tld)
        # 2) the parent domain contains 'domain.suffix', not just .suffix
        if not ext.suffix or ext.domain + '.' + ext.suffix in host_parts[1]:
            return host_parts[1]

        return host

    def load_cert(self, cn, overwrite=False,
                              wildcard=False,
                              wildcard_use_parent=False,
                              include_cache_key=False,
                              cert_ips=set(),
                              cert_fqdns=set(),
                              server=True):

        if server:
            is_ip = self.is_host_ip(cn)
  
            if is_ip:
                wildcard = False

            if wildcard and wildcard_use_parent:
                cn = self.get_wildcard_domain(cn)

            cert_ips = list(cert_ips)  # set to ordered list

        cert_str = None

        if not overwrite:
            cert_str = self.cert_cache.get(cn)

        # if cached, just read pem
        if cert_str:
            cert, key = self.read_pem(BytesIO(cert_str))
        else:
            if server:
            # if not cached, generate new root or host cert
                cert, key = self.generate_host_cert(cn,
                                                self.ca_cert,
                                                self.ca_key,
                                                wildcard,
                                                is_ip=is_ip,
                                                cert_ips=cert_ips,
                                                cert_fqdns=cert_fqdns)
            else:
                cert, key = self.generate_client_cert(cn,
                                                self.ca_cert,
                                                self.ca_key)
                

            # Write cert + key
            buff = BytesIO()
            self.write_pem(buff, cert, key)
            cert_str = buff.getvalue()

            # store cert in cache
            self.cert_cache[cn] = cert_str

        if not include_cache_key:
            return cert, key
        else:
            cache_key = cn
            if hasattr(self.cert_cache, 'key_for_cn'):
                cache_key = self.cert_cache.key_for_cn(cn)

            return cert, key, cache_key

    def cert_for_host(self, host, overwrite=False,
                                  wildcard=False,
                                  cert_ips=set(),
                                  cert_fqdns=set()):

        res = self.load_cert(host, overwrite=overwrite,
                                wildcard=wildcard,
                                wildcard_use_parent=False,
                                include_cache_key=True,
                                cert_ips=cert_ips,
                                cert_fqdns=cert_fqdns)

        return res[2]

    def get_wildcard_cert(self, cert_host, overwrite=False):
        res = self.load_cert(cert_host, overwrite=overwrite,
                                        wildcard=True,
                                        wildcard_use_parent=True,
                                        include_cache_key=True)

        return res[2]

    def get_root_PKCS12(self):
        p12 = crypto.PKCS12()
        p12.set_certificate(self.ca_cert)
        p12.set_privatekey(self.ca_key)
        return p12.export()

    def get_root_pem(self):
        return self.ca_file_cache.get(ROOT_CA)

    def get_root_pem_filename(self):
        return self.ca_file_cache.ca_file

    def _make_cert(self, certname):
        cert = crypto.X509()
        cert.set_serial_number(random.randint(0, 2 ** 64 - 1))
        cert.get_subject().CN = certname

        cert.set_version(2)
        cert.gmtime_adj_notBefore(self.cert_not_before)
        cert.gmtime_adj_notAfter(self.cert_not_after)
        return cert

    def generate_ca_root(self, ca_name, hash_func=DEF_HASH_FUNC):
        # Generate key
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # Generate cert
        cert = self._make_cert(ca_name)

        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(key)
        cert.add_extensions([
            crypto.X509Extension(b"basicConstraints",
                                 True,
                                 b"CA:TRUE, pathlen:0"),

            crypto.X509Extension(b"keyUsage",
                                 True,
                                 b"keyCertSign, cRLSign"),

            crypto.X509Extension(b"subjectKeyIdentifier",
                                 False,
                                 b"hash",
                                 subject=cert),
            ])
        cert.sign(key, hash_func)

        return cert, key

    def generate_host_cert(self, host, root_cert, root_key,
                           wildcard=False,
                           hash_func=DEF_HASH_FUNC,
                           is_ip=False,
                           cert_ips=set(),
                           cert_fqdns=set()):

        utf8_host = host.encode('utf-8')

        # Generate key
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # Generate CSR
        req = crypto.X509Req()
        req.get_subject().CN = utf8_host
        req.set_pubkey(key)
        req.sign(key, hash_func)

        # Generate Cert
        cert = self._make_cert(utf8_host)

        cert.set_issuer(root_cert.get_subject())
        cert.set_pubkey(req.get_pubkey())

        all_hosts = ['DNS:'+host]

        if wildcard:
            all_hosts += ['DNS:*.' + host]

        elif is_ip:
            all_hosts += ['IP:' + host]

        all_hosts += ['IP: {}'.format(ip) for ip in cert_ips]
        all_hosts += ['DNS: {}'.format(fqdn) for fqdn in cert_fqdns]

        san_hosts = ', '.join(all_hosts)
        san_hosts = san_hosts.encode('utf-8')

        cert.add_extensions([
            crypto.X509Extension(b"extendedKeyUsage", True, b"serverAuth"),
        ])
        cert.add_extensions([
            crypto.X509Extension(b'subjectAltName',
                                 False,
                                 san_hosts)])
        cert.sign(root_key, hash_func)
        return cert, key

    def generate_client_cert(self, cn, root_cert, root_key,
                           hash_func=DEF_HASH_FUNC):

        utf8_cn = cn.encode('utf-8')

        # Generate key
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, 2048)

        # Generate CSR
        req = crypto.X509Req()
        req.get_subject().CN = utf8_cn
        req.set_pubkey(key)
        req.sign(key, hash_func)

        # Generate Cert
        cert = self._make_cert(utf8_cn)

        cert.set_issuer(root_cert.get_subject())
        cert.set_pubkey(req.get_pubkey())

        cert.add_extensions([
            crypto.X509Extension(b"extendedKeyUsage", True, b"clientAuth"),
        ])
        cert.sign(root_key, hash_func)
        return cert, key

    def generate_crl(self,hash_func=DEF_HASH_FUNC):
        issuerCert = self.ca_cert
        issuerKey = self.ca_key
        digest='sha256'
        revokedList = self.cert_cache.get_revoked_list()
        crl = crypto.CRL()
        now = datetime.datetime.now()
        crl.set_lastUpdate(now.strftime('%Y%m%d%H%M%SZ').encode('utf-8'))
        crl.set_nextUpdate((now + datetime.timedelta(days=1)).strftime('%Y%m%d%H%M%SZ').encode('utf-8'))
        for revoked in revokedList:
            crl.add_revoked(revoked)
        crl.sign(issuerCert, issuerKey, hash_func.encode('utf8'))
        return crl
    
    def write_pem(self, buff, cert, key):
        buff.write(crypto.dump_privatekey(FILETYPE_PEM, key))
        buff.write(crypto.dump_certificate(FILETYPE_PEM, cert))

    def read_pem(self, buff):
        cert = crypto.load_certificate(FILETYPE_PEM, buff.read())
        buff.seek(0)
        key = crypto.load_privatekey(FILETYPE_PEM, buff.read())
        return cert, key

    def revoke_cert(self,cn):
        cert_string = self.cert_cache.get(cn)
        cert = self.cert_cache.revoke(cn,cert_string)
        
    def get_revoked(cert_str,revoked_date):
        cert = crypto.load_certificate(FILETYPE_PEM, cert_str.encode('utf-8'))
        revoked = crypto.Revoked()
        revoked.set_serial(('%x' % cert.get_serial_number()).encode('utf-8'))
        revoked.set_rev_date(revoked_date.strftime('%Y%m%d%H%M%SZ').encode('utf-8'))
        return revoked
    
# =================================================================
class SsmCache(object):
    def __init__(self, param_prefix,key_id=None):
        self._lock = threading.Lock()
        self.param_prefix = param_prefix if param_prefix.startswith('/') else f'/{param_prefix}'
        self.param_prefix = self.param_prefix if self.param_prefix.endswith('/') else f'{self.param_prefix}/'
        self.key_id=key_id
        self.ssm = boto3.client('ssm')
        self.modified = False

    def key_for_cn(self, cn):
        chars = re.escape(re.sub(r'[-_/.]','',string.punctuation))
        sanitized_key = re.sub(r'['+chars+']', '-',f'{self.param_prefix}{cn}/')
        return sanitized_key

    def revoked_key_for_cn(self, cn,timestamp=None):
        chars = re.escape(re.sub(r'[-_/.]','',string.punctuation))
        if not timestamp:
            timestamp = str(datetime.datetime.now().timestamp())
        sanitized_key = re.sub(r'['+chars+']', '-',f'{self.param_prefix}revoked/{timestamp}/{cn}/')
        return sanitized_key
    
    def revoked_date_for_key(self,key):
        match = re.match('.*/revoked/(.*?)/(.*?)/.*',key)
        if match:
            timestamp = match.group(1)
            cn = match.group(2)
            return timestamp,cn
        else:
            raise Exception(f'Key {key} format not recognized')

    def join_pem(self, cert, key):
        key = key if not key.endswith(b'\n') else key[:-1]
        cert = cert if not cert.endswith(b'\n') else cert[:-1]
        return(key+b'\n'+cert)        

    def split_pem(self, pem_str):
        key = pem_str.split('-----BEGIN CERTIFICATE-----')[0]
        key = key if not key.endswith('\n') else key[:-1]
        cert = pem_str.split('-----END PRIVATE KEY-----')[1]
        cert = cert if not cert.endswith('\n') else cert[:-1]
        return cert, key
                
    def __setitem__(self,cn,cert_string):        
        with self._lock:
            name = self.key_for_cn(cn)
            cert,key = self.split_pem(cert_string.decode('utf-8'))
            if self.key_id:
                self.ssm.put_parameter(Name=f'{name}PrivateKey',Value=key,Type='SecureString',KeyId=self.key_id, Overwrite=True)
                self.ssm.put_parameter(Name=f'{name}Certificate',Value=cert,Type='String',KeyId=self.key_id, Overwrite=True)
            else:
                self.ssm.put_parameter(Name=f'{name}PrivateKey',Value=key,Type='SecureString',Overwrite=True)
                self.ssm.put_parameter(Name=f'{name}Certificate',Value=cert,Type='String',Overwrite=True)
            self.modified = True
    
    def get(self, cn):
            name = self.key_for_cn(cn)
            print(name)
            try:
                key = self.ssm.get_parameter(Name=f'{name}PrivateKey',WithDecryption=True)['Parameter']['Value']
                key = key.encode()
                cert = self.ssm.get_parameter(Name=f'{name}Certificate')['Parameter']['Value']
                cert = cert.encode()
                cert_str = self.join_pem(cert, key)
                return cert_str
            except Exception as e:
                if 'ParameterNotFound' in str(e):
                    return(None)
                else:
                    raise(e)

    def get_revoked(self, cn,timestamp_str):
            name = self.revoked_key_for_cn(cn,timestamp_str)
            print(name)
            try:
                key = self.ssm.get_parameter(Name=f'{name}PrivateKey',WithDecryption=True)['Parameter']['Value']
                key = key.encode()
                cert = self.ssm.get_parameter(Name=f'{name}Certificate')['Parameter']['Value']
                cert = cert.encode()
                cert_str = self.join_pem(cert, key)
                return cert_str
            except Exception as e:
                if 'ParameterNotFound' in str(e):
                    return(None)
                else:
                    raise(e)
    
    def revoke(self,cn,cert_string):
        param = self.key_for_cn(cn)
        print(param)
        revoked_param = self.revoked_key_for_cn(cn)
        print(revoked_param)
        with self._lock:
            cert,key = self.split_pem(cert_string.decode('utf-8'))
            if self.key_id:
                self.ssm.put_parameter(Name=f'{revoked_param}PrivateKey',Value=key,Type='SecureString',KeyId=self.key_id, Overwrite=True)
                self.ssm.put_parameter(Name=f'{revoked_param}Certificate',Value=cert,Type='String',KeyId=self.key_id, Overwrite=True)
            else:
                self.ssm.put_parameter(Name=f'{revoked_param}PrivateKey',Value=key,Type='SecureString',Overwrite=True)
                self.ssm.put_parameter(Name=f'{revoked_param}Certificate',Value=cert,Type='String',Overwrite=True)
            self.modified = True
            self.ssm.delete_parameter(Name=f'{param}PrivateKey')
            self.ssm.delete_parameter(Name=f'{param}Certificate')
    
    def get_revoked_list(self):
        paginator = self.ssm.get_paginator('get_parameters_by_path')
        prefix = self.param_prefix
        iterator = paginator.paginate(Path=prefix,Recursive=True,WithDecryption=True)
        revoked_list = []
        for page in iterator:
            parameters = page['Parameters']
            for p in parameters:
                name = p['Name']
                if name.endswith('Certificate') and 'root_ca' not in name:
                    timestamp_str,cn=self.revoked_date_for_key(name)
                    revoked_date=datetime.datetime.fromtimestamp(float(timestamp_str))
                    print('CN:'+cn)
                    cert,key = self.split_pem(self.get_revoked(cn,timestamp_str).decode('utf-8'))
                    revoked = CertificateAuthority.get_revoked(cert, revoked_date)
                    revoked_list.append(revoked)
        return revoked_list

# =================================================================
class FileCache(object):
    def __init__(self, certs_dir):
        self._lock = threading.Lock()
        self.certs_dir = certs_dir
        self.modified = False

        if self.certs_dir and not os.path.exists(self.certs_dir):
            os.makedirs(self.certs_dir)

    def key_for_cn(self, cn):
        cn = cn.replace(':', '-')
        return os.path.join(self.certs_dir, cn) + '.pem'

    def revoked_key_for_cn(self, cn):
        cn = cn.replace(':', '-')
        timestamp = str(datetime.datetime.now().timestamp() * 1000)
        return os.path.join({self.certs_dir},'revoked',timestamp,cn) + '.pem'

    def __setitem__(self, cn, cert_string):
        filename = self.key_for_host(cn)
        with self._lock:
            with open(filename, 'wb') as fh:
                fh.write(cert_string)
                self.modified = True

    def get(self, cn):
        filename = self.key_for_host(cn)
        try:
            with open(filename, 'rb') as fh:
                return fh.read()
        except:
            return b''

    def revoke(self,cn):
        cert = self.get(cn)
        filename = self.key_for_cn(cn)
        revoked_filename = self.revoked_key_for_cn(cn)
        with self._lock:
            with open(revoked_filename, 'wb') as fh:
                fh.write(cert)
                self.modified = True
            os.remove(filename)

# =================================================================
class RootCACache(FileCache):
    def __init__(self, ca_file):
        self.ca_file = ca_file
        ca_dir = os.path.dirname(ca_file) or '.'
        super(RootCACache, self).__init__(ca_dir)

    def key_for_cn(self, cn=None):
        return self.ca_file

# =================================================================
class LRUCache(OrderedDict):
    def __init__(self, max_size):
        super(LRUCache, self).__init__()
        self.max_size = max_size

    def __setitem__(self, host, cert_string):
        super(LRUCache, self).__setitem__(host, cert_string)
        if len(self) > self.max_size:
            self.popitem(last=False)

def handler(event,context):
    args_str = event['args']
    print(args_str)
    print(f'Invoked as: {args_str}')
    args = shlex.split(args_str)
    main(args)

# =================================================================
def main(args=None):
    parser = ArgumentParser(description='Certificate Authority Cert Maker Tools')

    parser.add_argument('root_ca_cert',
                        help='Path to existing or new root CA file')

    parser.add_argument('-s', '--ssm', action='store_true', 
                        help='Use AWS SSM to store certificates under prefix given by the path argument')

    parser.add_argument('-r', '--revoke', action='store_true',
                        help='Revoke the certificate give by -n or -l. Root certificate cannot be revoked')

    parser.add_argument('-R', '--revoke-list', action='store',
                        help='Generate a CRL and store it in the specified destination')

    parser.add_argument('-c', '--certname', action='store', default=CERT_NAME,
                        help='Name for root certificate')

    parser.add_argument('-n', '--hostname',
                        help='Hostname certificate to create')

    parser.add_argument('-l', '--clientname',
                        help='Client name certificate to create')

    parser.add_argument('-d', '--certs-dir', default=CERTS_DIR,
                        help='Directory for host certificates')

    parser.add_argument('-f', '--force', action='store_true',
                        help='Overwrite certificates if they already exist')

    parser.add_argument('-w', '--wildcard_cert', action='store_true',
                        help='add wildcard SAN to host: *.<host>, <host>')

    parser.add_argument('-I', '--cert_ips', action='store', default='',
                        help='add IPs to the cert\'s SAN')

    parser.add_argument('-D', '--cert_fqdns', action='store', default='',
                        help='add more domains to the cert\'s SAN')

    r = parser.parse_args(args=args)

    certs_dir = r.certs_dir
    wildcard = r.wildcard_cert

    root_cert = r.root_ca_cert
    hostname = r.hostname
    clientname = r.clientname

    if r.cert_ips != '':
        cert_ips = r.cert_ips.split(',')
    else:
        cert_ips = []
    if r.cert_fqdns != '':
        cert_fqdns = r.cert_fqdns.split(',')
    else:
        cert_fqdns = []

    if not hostname and not clientname:
        overwrite = r.force
    else:
        overwrite = False

    if not r.ssm:    
      cert_cache = FileCache(certs_dir)
      ca_file_cache = RootCACache(root_cert)
    else:
      print('Using SSM')
      cert_cache = SsmCache(root_cert)
      ca_file_cache = SsmCache(root_cert)

    ca = CertificateAuthority(ca_name=r.certname,
                              ca_file_cache=ca_file_cache,
                              cert_cache=cert_cache,
                              overwrite=overwrite)
    
    # Just creating the root cert
    if not hostname and not clientname:
        if r.revoke_list:
            crl = ca.generate_crl()
            crl_pem = crypto.dump_crl(crypto.FILETYPE_PEM, crl)
            if r.revoke_list.startswith('s3://'):
                match = re.match('s3://(.*?)/(.*)',r.revoke_list)
                bucket = match.group(1)
                key = match.group(2)
                s3 = boto3.resource('s3')
                content = s3.Object(bucket,key).put(Body=crl_pem)
            else:
                with open(r.revoke_list,'wb') as f:
                    f.write(crl_pem)
            return 0
            
        if ca_file_cache.modified:
            print('Created new root cert: "' + root_cert + '"')
            return 0
        else:
            print('Root cert "' + root_cert +
                  '" already exists,' + ' use -f to overwrite')
            return 1

    # Sign a certificate for a given host
    overwrite = r.force

    if r.revoke:
        if not hostname and not clientname:
            print('Root cert can not be revoked. Use -r only with -n or -l')
            return 1
        else:
            certName = hostname if hostname else clientname
            ca.revoke_cert(certName)
    else:
        if hostname:
            certName = hostname
            ca.load_cert(certName, overwrite=overwrite,
                           wildcard=wildcard,
                           wildcard_use_parent=False,
                           cert_ips=cert_ips,
                           cert_fqdns=cert_fqdns,
                           server=True)
        else:
            certName = clientname
            ca.load_cert(certName, overwrite=overwrite, server=False)

        if cert_cache.modified:
            print('Created new cert "' + certName +
                  '" signed by root cert ' +
                  root_cert)
            return 0
        else:
            print('Cert for "' + certName + '" already exists,' +
                  ' use -f to overwrite')
            return 1

if __name__ == "__main__":  #pragma: no cover
#    handler({"args":"ClientVPN -c \"DXC LZ SBX Client VPN CA\" -s "},None)
    main()
