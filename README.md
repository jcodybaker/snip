# TLS SNIp - An SNI Based Proxy

## What is TLS?
Transport Layer Security (TLS), known as SSL (Secure Socket Layer) in previous protocol versions, is used to secure 
network communications between two application end-points (generally client and server software).  TLS provides
mechanisms to verify the identity of each endpoint as well as the privacy and integrity of communicated data.  Because 
TLS maintains the semantics of the underlying duplex-stream protocol (TCP in most cases) it is well suited to retro-fit 
existing stream based protocols. For example, Secure HTTP (HTTPS) is the common HTTP Protocol streamed over a TLS
connection.


## What is SNI?
Server Name Indication (SNI) is a TLS extension proposed in RFC 4366 (dated April 2006).  SNI provides for an optional
clear-text indication of the target server's address in the opening phase of communication.  SNI allows TLS servers with 
credentials for multiple identities to select and transmit a client-requested identity instead of blindly providing a 
single identity. As an example, virtual website hosting providers can use an SNI-enabled HTTPS servers to host multiple
secure website certificate identities on the same IP address and port.  Without SNI HTTPS servers can only effectively 
serve one certificate identity per IP address.  In practice this results in wastes IPv4 addresses which have non-trivial
costs and are in short demand. SNI support is commonly enabled in modern web browsers; see below for more details.

## SNI Proxying
In SNI Proxying we use the client's Server Name Indication not to select an identity locally, but instead to select a
target server which can provide that identity.  Once the target has been determined, the proxy server connects and
begins relaying data between the client and target.  The TLS negotiation occurs between the client and target server; 
the proxy relays the handshake and encrypted data, but is not a party to the unencrypted communication.  

## Use Cases

### Mixed Platform HTTPS Hosting


## Todo

- Regex matching / targets
- chrome support
- TLS tests
- configure default routes
- documentation
- more configuration validation
- windows