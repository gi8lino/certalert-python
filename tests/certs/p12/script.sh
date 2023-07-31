openssl genpkey -algorithm RSA -out private_key.key
openssl req -new -x509 -key private_key.key -out self_signed_certificate.crt -days 365
openssl pkcs12 -export -out certificate.p12 -inkey private_key.key -in self_signed_certificate.crt
