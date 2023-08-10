# DEPRECATED WARNING

This was only a POC. Use http://github.com/containeroo/certalert instead.

# certalert - Certificate Expiration Exporter

certalert is a Python script designed to extract certificate expiration dates and send them as metrics to the Prometheus Pushgateway. It is especially useful for monitoring certificate expirations in a Prometheus-based monitoring environment.

## Certificate Types

certalert supports the following types of certificates:

- CRT: Standard certificate format with the `.crt` file extension.
- PEM: Standard certificate format with the `.pem` file extension.
- PKCS12 (P12): Certificate format with the `.p12` file extension.
- Java Keystore (JKS): Certificate format with the `.jks` file extension.

## Examples

You can find example Kubernetes manifests in the ./deploy directory

If you have a special constellation the script does not cover, create a Issue or PR or use an initContainer to extract the certificate.
