# VPN
This is a simple client-server VPN implementation (part of Internet Security course)

It consists of two phases.
First, a handshake is performed between the client and the server. X509 certificates are used to identify both sides. In the final step of the handshake, a symmetric key is established between the two sides.

In the second phase, we use AES (with the symmetric key) to encrypt data. A two-way stream is created. Both sides can send and receive encrypted data using the same key.

Finally, when one side shuts down the communication, both sides exit gracefully.
