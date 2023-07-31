# without password
openssl genpkey -algorithm RSA -out private_key.key
openssl req -new -key private_key.key -out certificate.csr
openssl x509 -req -in certificate.csr -signkey private_key.key -out certificate.pem
cat private_key.key certificate.pem > certificate_no_password.pem


# with password
openssl genpkey -algorithm RSA -aes256 -out private_key.key
openssl req -new -key private_key.key -out certificate.csr
openssl x509 -req -in certificate.csr -signkey private_key.key -out certificate.pem
cat private_key.key certificate.pem > certificate_with_password.pem
