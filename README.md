# Certinator - Certificate Expiration Exporter

Certinator is a Python script designed to extract certificate expiration dates and send them as metrics to the Prometheus Pushgateway. It is especially useful for monitoring certificate expirations in a Prometheus-based monitoring environment.

## Certificate Types

Certinator supports three types of certificates:

- PEM: Standard certificate format with the `.pem` file extension.
- PKCS12 (P12): Certificate format with the `.p12` file extension.
- Java Keystore (JKS): Certificate format with the `.jks` file extension.

## Examples

You can find example Kubernetes manifests in the ./deploy directory
