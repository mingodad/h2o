? my $ctx = $main::context;
? $_mt->wrapper_file("wrapper.mt", "Configure", "Base Directives")->(sub {

<p>
This document describes the configuration directives common to all the protocols and handlers.
</p>

<?
$ctx->{directive}->(
    name   => "hosts",
    levels => [ qw(global) ],
    desc   => q{Maps <code>host:port</code> to the mappings of per-host configs.},
)->(sub {
?>
<p>
The directive specifies the mapping between the authorities (the host or <code>host:port</code> section of an URL) and their configurations.
The directive is mandatory, and must at least contain one entry.
</p>
<p>
When <code>port</code> is omitted, the entry will match the requests targetting the default ports (i.e. port 80 for HTTP, port 443 for HTTPS) with given hostname.
Otherwise, the entry will match the requests targetting the specified port.
</p>
<p>
Wildcard character <code>*</code> can be used as the first component of the hostname.
If used, they are matched using the rule defined in <a href="https://tools.ietf.org/html/rfc2818#section-3.1" target="_blank">RFC 2818 Section 3.1</a>.
For example, <code>*.example.com</code> will match HTTP requests for both <code>foo.example.com</code> and <code>bar.example.com</code>.
Note that an exact match is preferred over host definitions using wildcard characters.
</p>


<?= $ctx->{example}->('A host redirecting all HTTP requests to HTTPS', <<'EOT');
hosts:
  "www.example.com:80":
    listen:
      port: 80
    paths:
      "/":
        redirect: https://www.example.com/
  "www.example.com:443":
    listen:
      port: 443
      ssl:
        key-file: /path/to/ssl-key-file
        certificate-file: /path/to/ssl-certificate-file
    paths:
      "/":
        file.dir: /path/to/doc-root
EOT
?>
? })

<?
$ctx->{directive}->(
    name   => "paths",
    levels => [ qw(host) ],
    desc   => q{Mapping of paths and their configurations.},
)->(sub {
?>
</p>
<p>
The mapping is searched using prefix-match.
The entry with the longest path is chosen when more than one matching paths were found.
An <code>404 Not Found</code> error is returned if no matching paths were found.
</p>
<?= $ctx->{example}->('Configuration with two paths', <<'EOT')
hosts:
  "www.example.com":
    listen:
      port: 80
    paths:
      "/":
        file.dir: /path/to/doc-root
      "/assets":
        file.dir: /path/to/assets
EOT
?>
? })

<?
$ctx->{directive}->(
    name   => "listen",
    levels => [ qw(global host) ],
    desc   => q{Specifies the port at which the server should listen to.},
)->(sub {
?>
</p>
<p>
In addition to specifying the port number, it is also possible to designate the bind address or the SSL configuration.
</p>
<?= $ctx->{example}->('Various ways of using the Listen Directive', <<'EOT')
# accept HTTP on port 80 on default address (both IPv4 and IPv6)
listen: 80

# accept HTTP on 127.0.0.1:8080
listen:
  host: 127.0.0.1
  port: 8080

# accept HTTPS on port 443
listen:
  port: 443
  ssl:
    key-file: /path/to/key-file
    certificate-file: /path/to/certificate-file

# accept HTTPS on port 443 (using PROXY protocol)
listen:
  port: 443
  ssl:
    key-file: /path/to/key-file
    certificate-file: /path/to/certificate-file
  proxy-protocol: ON
EOT
?>
<h4 id="listen-configuration-levels">Configuration Levels</h4>
<p>
The directive can be used either at global-level or at host-level.
At least one <code>listen</code> directive must exist at the global level, or every <i>host</i>-level configuration must have at least one <code>listen</code> directive.
</p>
<p>
Incoming connections accepted by global-level listeners will be dispatched to one of the host-level contexts with the corresponding <code>host:port</code>, or to the first host-level context if none of the contexts were given <code>host:port</code> corresponding to the request.
</p>
<p>
Host-level listeners specify bind addresses specific to the host-level context.
However it is permitted to specify the same bind address for more than one host-level contexts, in which case hostname-based lookup will be performed between the host contexts that share the address.
The feature is useful for setting up a HTTPS virtual host using <a href="https://tools.ietf.org/html/rfc6066">Server-Name Indication (RFC 6066)</a>.
</p>
<?= $ctx->{example}->('Using host-level listeners for HTTPS virtual-hosting', <<'EOT')
hosts:
  "www.example.com:443":
    listen:
      port: 443
      ssl:
        key-file: /path/to/www_example_com.key
        certificate-file: /path/to/www_example_com.crt
    paths:
      "/":
        file.dir: /path/to/doc-root_of_www_example_com
  "www.example.jp:443":
    listen:
      port: 443
      ssl:
        key-file: /path/to/www_example_jp.key
        certificate-file: /path/to/www_example_jp.crt
    paths:
      "/":
        file.dir: /path/to/doc-root_of_www_example_jp
EOT
?>
<h4 id="listen-ssl">SSL Attribute</h4>
<p>
The <code style="font-weight: bold;">ssl</code> attribute must be defined as a mapping, and recognizes the following attributes.
</p>
<dl>
<dt id="certificate-file">certificate-file:</dt>
<dd>path of the SSL certificate file (mandatory)</dd>
<dt id="key-file">key-file:</dt>
<dd>path of the SSL private key file (mandatory)</dd>
<dt id="minimum-version">minimum-version:</dt>
<dd>
minimum protocol version, should be one of: <code>SSLv2</code>, <code>SSLv3</code>, <code>TLSv1</code>, <code>TLSv1.1</code>, <code>TLSv1.2</code>.
Default is <code>TLSv1</code>
</dd>
<dt id="cipher-suite">cipher-suite:</dt>
<dd>list of cipher suites to be passed to OpenSSL via SSL_CTX_set_cipher_list (optional)</dd>
<dt id="cipher-preferences">cipher-preference:</dt>
<dd>
side of the list that should be used for selecting the cipher-suite; should be either of: <code>client</code>, <code>server</code>.
Default is <code>client</code>.
</dd>
<dt id="dh-file">dh-file:</dt>
<dd>
path of a PEM file containing the Diffie-Hellman paratemers to be used.
Use of the file is recommended for servers using Diffie-Hellman key agreement.
(optional)
</dd>
<dt id="ocsp-update-interval">ocsp-update-interval:</dt>
<dd>
interval for updating the OCSP stapling data (in seconds), or set to zero to disable OCSP stapling.
Default is <code>14400</code> (4 hours).
</dd>
<dt id="ocsp-max-failures">ocsp-max-failures:</dt>
<dd>
number of consecutive OCSP queriy failures before stopping to send OCSP stapling data to the client.
Default is 3.
</dd>
<dt id="neverbleed">neverbleed:</dt>
<dd>
unless set to <code>OFF</code>, H2O isolates RSA private key operations to an islotated process by using <a href="https://github.com/h2o/neverbleed">Neverbleed</a>.
Default is <code>ON</code>.
</dl>
<p>
<a href="configure/base_directives.html#ssl-session-resumption"><code>ssl-session-resumption</code></a> directive is provided for tuning parameters related to session resumption and session tickets.
</p>
<h4 id="listen-proxy-protocol">The Proxy-Protocol Attribute</h4>
<p>
The <code>proxy-protocol</code> attribute (i.e. the value of the attribute must be either <code>ON</code> or <code>OFF</code>) specifies if the server should recognize the information passed via <a href="http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt">"the PROXY protocol</a> in the incoming connections.
The protocol is used by L4 gateways such as <a href="http://aws.amazon.com/jp/elasticloadbalancing/">AWS Elastic Load Balancing</a> to send peer address to the servers behind the gateways.
</p>
<p>
When set to <code>ON</code>, H2O standalone server tries to parse the first octets of the incoming connections as defined in version 1 of the specification, and if successful, passes the addresses obtained from the protocol to the web applications and the logging handlers.
If the first octets do not accord with the specification, it is considered as the start of the SSL handshake or as the beginning of an HTTP request depending on whether if the <code>ssl</code> attribute has been used.
</p>
<p>
Default is <code>OFF</code>.
</p>
<h4 id="listen-unix-socket">Listening to a Unix Socket</h4>
<p>
If the <code>type</code> attribute is set to <code>unix</code>, then the <code>port</code> attribute is assumed to specify the path of the unix socket to which the standalone server should bound.
Also following attributes are recognized.
</p>
<dl>
<dt>owner</dt>
<dd>
username of the owner of the socket file.
If omitted, the socket file will be owned by the launching user.
</dd>
<dt>permission</dt>
<dd>
an octal number specifying the permission of the sokcet file.
Many operating systems require write permission for connecting to the socket file.
If omitted, the permission of the socket file will reflect the umask of the calling process.
</dd>
</dl>
<?= $ctx->{example}->('Listening to a Unix Socket accessible only by www-data', <<'EOT')
listen:
  type:       unix
  port:       /tmp/h2o.sock
  owner:      www-data
  permission: 600
EOT
?>
? })

<?
$ctx->{directive}->(
    name   => "error-log",
    levels => [ qw(global) ],
    desc   => q{Path of the file to which error logs should be appended.},
)->(sub {
?>
<p>
Default is stderr.
</p>
<p>
If the path starts with <code>|</code>, the rest of the path is considered as a command to which the logs should be piped.
</p>
<?= $ctx->{example}->('Log errors to file', <<'EOT')
error-log: /path/to/error-log-file
EOT
?>
<?= $ctx->{example}->('Log errors through pipe', <<'EOT')
error-log: "| rotatelogs /path/to/error-log-file.%Y%m%d 86400"
EOT
?>
? })

<?
$ctx->{directive}->(
    name   => "limit-request-body",
    levels => [ qw(global) ],
    desc   => q{Maximum size of request body in bytes (e.g. content of POST).},
)->(sub {
?>
<p>
Default is 1073741824 (1GB).
</p>
? })

<?
$ctx->{directive}->(
    name    => "max-connections",
    levels  => [ qw(global) ],
    default => 'max-connections: 1024',
    desc    => q{Number of connections to handle at once at maximum.},
)->(sub {});

$ctx->{directive}->(
    name    => "max-delegations",
    levels  => [ qw(global) ],
    default => 'max-delegations: 5',
    desc    => q{Limits the number of delegations (i.e. internal redirects using the <code>X-Reproxy-URL</code> header).},
)->(sub {});

$ctx->{directive}->(
    name    => "num-name-resolution-threads",
    levels  => [ qw(global) ],
    default => 'num-name-resolution-threads: 32',
    desc    => q{Number of threads to run for name resolution.},
)->(sub {});
?>

<?
$ctx->{directive}->(
    name   => "num-threads",
    levels => [ qw(global) ],
    desc   => q{Number of worker threads.},
)->(sub {
?>
<p>
Default is the number of the processors connected to the system as obtained by <code>getconf NPROCESSORS_ONLN</code>.
</p>
? })

<?
$ctx->{directive}->(
    name   => "pid-file",
    levels => [ qw(global) ],
    desc   => q{Name of the file to which the process id of the server should be written.},
)->(sub {
?>
<p>
Default is none.
</p>
? })

<?
$ctx->{directive}->(
    name   => "tcp-fastopen",
    levels => [ qw(global) ],
    desc   => q{Size of the queue used for TCP Fast Open.},
)->(sub {
?>
<p>
<a href="https://en.wikipedia.org/wiki/TCP_Fast_Open">TCP Fast Open</a> is an extension to the TCP/IP protocol that reduces the time spent for establishing a connection.
On Linux that support the feature, the default value is <code>4,096</code>.
On other platforms the default value is <code>0</code> (disabled).
</p>
? })

<?
$ctx->{directive}->(
    name   => "ssl-session-resumption",
    levels => [ qw(global) ],
    desc   => q{Configures cache-based and ticket-based session resumption.},
)->(sub {
?>
<p>
To reduce the latency introduced by the TLS (SSL) handshake, two methods to resume a previous encrypted session are defined by the Internet Engineering Task Force.
H2O supports both of the methods: cache-based session resumption (defined in <a href="https://tools.ietf.org/html/rfc5246">RFC 5246</a>) and ticket-based session resumption (defined in <a href="https://tools.ietf.org/html/rfc5077">RFC 5077</a>).
</p>
<?= $ctx->{example}->('Various session-resumption configurations', <<'EOT');
# use both methods (storing data on internal memory)
ssl-session-resumption:
    mode: all

# use both methods (storing data on memcached running at 192.168.0.4:11211)
ssl-session-resumption:
    mode: all
    cache-store: memcached
    ticket-store: memcached
    cache-memcached-num-threads: 8
    memcached:
        host: 192.168.0.4
        port: 11211

# use ticket-based resumption only (with secrets used for encrypting the tickets stored in a file)
ssl-session-resumption:
    mode: ticket
    ticket-store: file
    ticket-file: /path/to/ticket-secrets.yaml
EOT
?>
<h4 id="ssl-session-resumption-methods">Defining the Methods Used</h4>
<p>
The <code>mode</code> attribute defines which methods should be used for resuming the TLS sessions.
The value can be either of: <code>off</code>, <code>cache</code>, <code>ticket</code>, <code>all</code>.
Default is <code>all</code>.
</p>
<p>
If set to <code>off</code>, session resumption will be disabled, and all TLS connections will be established via full handshakes.
If set to <code>all</code>, both session-based and ticket-based resumptions will be used, with the preference given to the ticket-based resumption for clients supporting both the methods.
</p>
<p>
For each method, additional attributes can be used to customize their behaviors.
Attributes that modify the behavior of the disabled method are ignored.
</p>
<h4 id="ssl-session-resumption-cache-based">Attributes for Cache-based Resumption</h4>
<p>
Following attributes are recognized if the cache-based session resumption is enabled.
Note that <code>memcached</code> attribute must be defined as well in case the <code>memcached</code> cache-store is used.
</p>
<dl>
<dt>cache-store:</dt>
<dd>
defines where the cache should be stored, must be one of: <code>internal</code>, <code>memcached</code>.
Default is <code>internal</code>.
</dd>
<dt>cache-memcached-num-threads:</dt>
<dd>defines the maximum number of threads used for communicating with the memcached server.
Default is <code>1</code>.
</dd>
<dt>cache-memcached-prefix:</dt>
<dd>
for the <code>memcached</code> store specifies the key prefix used to store the secrets on memcached.
Default is <code>h2o:ssl-session-cache:</code>.
</dd>
</dl>
<h4 id="ssl-session-resumption-ticket-based">Attributes for Ticket-based Resumption</h4>
<p>
Ticket-based session resumption uses master secret(s) to encrypt the keys used for encrypting the data transmitted over TLS connections.
To achieve <a href="https://en.wikipedia.org/wiki/Forward_secrecy" target="_blank">forward-secrecy</a> (i.e. protect past communications from being decrypted in case a master secret gets obtained by a third party), it is essential to periodically change the secret and remove the old ones.
</p>
<p>
Among the three types of stores supported for ticket-based session remusption, the <code>internal</code> store and <code>memcached</code> store implement automatic roll-over of the secrets.
A new master secret is created every 1/4 of the session lifetime (defined by the <code>lifetime</code> attribute), and they expire (and gets removed) after 5/4 of the session lifetime elapse.
</p>
<p>
For the <code>file</code> store, it is the responsibility of the web-site administrator to periodically update the secrets.  H2O monitors the file and reloads the secrets when the file is altered.
</p>
<p>
Following attributes are recognized if the ticket-based resumption is enabled.
</p>
<dl>
<dt>ticket-store:</dt>
<dd>defines where the secrets for ticket-based resumption should be / is stored, must be one of: <code>internal</code>, <code>file</code>, <code>memcached</code>.
Default is <code>internal</code>.
<dt>ticket-cipher:</dt>
<dd>
for stores that implement automatic roll-over, specifies the cipher used for encrypting the tickets.
The value must be one recognizable by <code>EVP_get_cipherbyname</code>.
Default is <code>aes-256-cbc</code>.
<dt>ticket-hash:</dt>
<dd>
for stores that implement automatic roll-over, specifies the cipher used for digitally-signing the tickets.
The value must be one recognizable by <code>EVP_get_digestbyname</code>.
Default is <code>sha-256</code>.
</dd>
<dt>ticket-file:</dt>
<dd>for the <code>file</code> store specifies the file in which the secrets are stored</dd>
<dt>ticket-memcached-key:</dt>
<dd>
for the <code>memcached</code> store specifies the key used to store the secrets on memcached.
Default is <code>h2o:ssl-session-ticket</code>.
</dd>
</dl>
<h4 id="ssl-session-resumption-other">Other Attributes</h4>
<p>
Following attributes are common to cache-based and ticket-based session resumption.
</p>
<dl>
<dt>lifetime:</dt>
<dd>
defines the lifetime of a TLS session; when it expires the session cache entry is purged, and establishing a new connection will require a full TLS handshake.
Default value is <code>3600</code> (in seconds).
</dd>
<dt>memcached:</dt>
<dd>
specifies the location of memcached used by the <code>memcached</code> stores.
The value must be a mapping with <code>host</code> attribute specifying the address of the memcached server, and optionally a <code>port</code> attribute specifying the port number (default is <code>11211</code>).
</dd>
? })

<?
$ctx->{directive}->(
    name   => "user",
    levels => [ qw(global) ],
    desc   => q{Username under which the server should handle incoming requests.},
)->(sub {
?>
<p>
If the directive is omitted and if the server is started under root privileges, the server will attempt to <code>setuid</code> to <code>nobody</code>.
</p>
? })

? })
