DXC Iberia Extensions
=====================

DXC Iberia has extended certauth to a new use case where certificates are stored in AWS SSM Parameter Store,
and to be able to generate client certificates too.

Certificate revocation and CRL generation are added too

Certificate Authority Certificate Maker Tools
=============================================

.. image:: https://travis-ci.org/ikreymer/certauth.svg?branch=master
    :target: https://travis-ci.org/ikreymer/certauth
.. image:: https://coveralls.io/repos/ikreymer/certauth/badge.svg?branch=master
    :target: https://coveralls.io/r/ikreymer/certauth?branch=master

This package provides a small library, built on top of ``pyOpenSSL``, which allows for creating a custom certificate authority certificate,
and genereating on-demand dynamic host certs using that CA certificate.

It is most useful for use with a man-in-the-middle HTTPS proxy, for example, for recording or replaying web content.

Trusting the CA created by this tool should be used with caution in a controlled setting to avoid security risks.


CertificateAuthority API
============================

The ``CertificateAuthority`` class provides an interface to manage a root CA and generate dynamic host certificates suitable
for use with the native Python ``ssl`` library as well as pyOpenSSL ``SSL`` module.

The class provides several options for storing the root CA and generated host CAs.


File-based Certificate Cache
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

   ca = CertificateAuthority('My Custom CA', 'my-ca.pem', cert_cache='/tmp/certs')
   filename = ca.cert_for_host('example.com')

In this configuration, the root CA is stored at ``my-ca.pem`` and dynamically generated certs
are placed in ``/tmp/certs``. The ``filename`` returned would be ``/tmp/certs/example.com.pem`` in this example.

This filename can then be used with the Python `ssl.load_cert_chain(certfile) <https://docs.python.org/3/library/ssl.html#ssl.SSLContext.load_cert_chain>`_ command.

Note that the dynamically created certs are never deleted by ``certauth``, it remains up to the user to handle cleanup occasionally if desired.


In-memory Certificate Cache
~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

   ca = CertificateAuthority('My Custom CA', 'my-ca.pem', cert_cache=50)
   cert, key = ca.load_cert('example.com')
   
This configuration stores the root CA at ``my-ca.pem`` but uses an in-memory certificate cache for dynamically created certs. 
These certs are stored in an LRU cache, configured to keep at most 50 certs.

The ``cert`` and ``key`` can then be used with `OpenSSL.SSL.Context.use_certificate <http://www.pyopenssl.org/en/stable/api/ssl.html#OpenSSL.SSL.Context.use_certificate>`_

.. code:: python

        context = SSl.Context(...)
        context.use_privatekey(key)
        context.use_certificate(cert)


Custom Cache
~~~~~~~~~~~~

A custom cache implementations which stores and retrieves per-host certificates can also be provided:

.. code:: python

   ca = CertificateAuthority('My Custom CA', 'my-ca.pem', cert_cache=CustomCache())
   cert, key = ca.load_cert('example.com')
   
   class CustomCache:
       def __setitem__(self, host, cert_string):
          # store cert_string for host
          
       def get(self, host):
          # return cached cert_string, if available
          cert_string = ...
          return cert_string

AWS SSM Cache
~~~~~~~~~~~~

A custom cache that stores certificates under an AWS SSM Paremeter Store prefix.

SSM parameters are limited to letters, digits and the symbols / . - and _ where / are interpreted as path separators.

Certificate names are modified replacing any other symbol besides these by - 

The AWS client environment must provide a proper way for the SDK to find credentials and the default region, for 
example setting them in the environment or in the credentials and/or config files.

Wildcard Certs
~~~~~~~~~~~~~~

To reduce the number of certs generated, it is convenient to generate wildcard certs.

.. code:: python

   cert, key = ca.load_cert('example.com', wildcard=True)

This will generate a cert for ``*.example.com``.

To automatically generate a wildcard cert for parent domain, use:

.. code:: python

   cert, key = ca.load_cert('test.example.com', wildcard=True, wildcard_for_parent=True)

This will also generate a cert for ``*.example.com``

Starting with 1.3.0, ``certauth`` uses ``tldextract`` to determine the tld for a given host,
and will not use a parent domain if it is itself a tld suffix.

For example, calling:

.. code:: python

   cert, key = ca.load_cert('example.co.uk', wildcard=True, wildcard_for_parent=True)
   
will now result in a cert for ``*.example.co.uk``, not ``*.co.uk``.


Alternative FQDNs or IPs in SAN
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Sometimes, you want to add alternative FQDNs or IPs as Subject Alternative Names
to your certificate. To do that, simply use the ``cert_fqdns`` or ``cert_ips``
params of ``load_cert``:

.. code:: python

   cert, key = ca.load_cert('example.com', cert_fqdns=['example.org'], cert_ips=['192.168.1.1'])

This will generate a cert for ``example.com`` with ``example.org`` and ``192.168.1.1`` in
the SAN.

Certificate Revocation
~~~~~~~~~~~~~~~~~~~~~~

Certificates can be revocated with the -r option combined with -l for client certificates or -n for server certificates
Revocated certificates are relocated to a different location in the cache. Teh CRL generation retrieves all certificates
in the revocated location and generates a CRL signed by the CA with 'next_update' set by default to 24 hours later. Common
use of 'next_update' by CRL consumers is that the CRL is considered invalid an needs to be reloaded after the said date.

The CRL is generated using the -R option followed to the file or S3 URI where the CRL file is stored. Storing the CRL as 
an AWS SSM parameter is not supported as CRL size can easily exceed the 8KB limit of AWS SSM parameters.

A certificate can be un-revoked my relocating it in the original location but this operation is not provided by this application
and must be done manually. In case a certificate is un-revoked and was included in a CRL, any published CRL must be updated.

AWS ACM Import
~~~~~~~~~~~~~~

With option -A a certificate that already exists, or the root_ca, is imported into AWS ACM. This is useful to use the certificates 
in any AWS ACM integrated services, such as Client VPN, ELB, etc.


CLI Usage Examples
==================

``certauth`` also includes a simple command-line API for certificate creation and management.

::

  usage: certauth [-h] [-c CERTNAME] [-n HOSTNAME] [-d CERTS_DIR] [-w] [-I IP_LIST] [-D FQDN_LIST] [-l CLIENT_NAME] [-s] [-f] [-r] [-R REVOCATION_LIST] [-A]
                

  positional arguments:
    root_ca_cert          Path to existing or new root CA file

  optional arguments:
    -h, --help            show this help message and exit
    -c CERTNAME, --certname CERTNAME
                        Name for root certificate
    -n HOSTNAME, --hostname HOSTNAME
                        Hostname certificate to create
    -w, --wildcard_cert   
                        Add wildcard SAN to host: *.<host>, <host>. Ignored if '-l' is present and '-n' is not
    -I, --cert_ips IP_LIST
                        Adds the IPS given in the comma separated argument. '-w' is ignored. Only used with '-n'
    -D, --cert_fqdns FQDN_LIST
                        Adds the FQDN names in the comma separated argument. Only used with '-n'
    -l CLIENT_NAME --clientname CLIENT_NAME
                        Name of the client certificate to create. Ignored if '-n' is present
    -s --ssm
                        Use AWS SSM Parameter store as certificate store, under prefix given by 'root_ca_cert'
    -d CERTS_DIR, --certs-dir CERTS_DIR
                        Directory for host certificates. Ignored if '-s' is present
    -f, --force           Overwrite certificates if they already exist
    
    -r, --revoke
                        Combined with -l or -n to specify the cn, revocates the indicated certificate
    -R, --revoke_list REVOKE_LIST
                        Generates a CRL file with next update in 365 days and stores it at `REVOKE_LIST`, that can be a local file or an S3 obejct URI
    -A, --acm-import
                        Imports the certificate with CN given by -n or -l to AWS ACM. If -n or -l is not given the root_ca is imported

To create a new root CA certificate:

``certauth myrootca.pem --certname "My Test CA"``

To create a host certificate signed with CA certificate in directory ``certs_dir``:

``certauth myrootca.pem --hostname "example.com" -d ./certs_dir``

If the root cert doesn't exist, it'll be created automatically.
If ``certs_dir``, doesn't exist, it'll be created automatically also.

The cert for ``example.com`` will be created as ``certs_dir/example.com.pem``.
If it already exists, it will not be overwritten (unless ``-f`` option is used).

The ``-w`` option can be used to create a wildcard cert which has subject alternate names (SAN) for ``example.com`` and ``*.example.com``

To create a client certificate

``certauth myrootca.pem --clientname "example" -d ./certs_dir``

To create a CA in AWS SSM:

``certauth /CA/MyRootCA -c "MY Test CA"``

To create certificates in AWS SSM:

``certauth /CA/MyRootCA -s --clientname jalvarezferr@dxc.com``
``certauth /CA/MyRootCA --ssm_prefix MyRootCA --hostname "example.com"``

To revoke a certificate

``certauth /CA/MyRootCA -s -l jalvarezferr@dxc.com -r``

To generate a CRL stored in AWS S3:

``certauth /CA/MyRootCA -s -R s3://myca-bucket/crl.pem``

To import a certificate in AWS ACM:

``certauth /CA/MyRootCA -s -n server.mydomain.com -A``

History
=======

The CertificateAuthority functionality has evolved from certificate management originally found in the man-in-the-middle proxy `pymiproxy <https://github.com/allfro/pymiproxy>`_ by Nadeem Douba.

It was also extended in `warcprox <https://github.com/internetarchive/warcprox>`_ by `Noah Levitt <https://github.com/nlevitt>`_ of Internet Archive.

The CA functionality was also reused in `pywb <https://github.com/ikreymer/pywb>`_ and finally factored out into this separate package for modularity.

It is now also used by `wsgiprox <https://github.com/webrecorder/wsgiprox>`_ to provide a generalized HTTPS proxy wrapper to any WSGI application.


