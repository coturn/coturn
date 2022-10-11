#!/bin/bash

fail_on_error() {
  local result=$?
  if [ $result -ne 0 ] ; then
    echo "Error: $1"
    exit 1
  else
    echo "Success: $1"
  fi
}

faketime --help >/dev/null 2>/dev/null
fail_on_error "faketime utility needed, run sudo apt install faketime"

##################################################
# Generate the CA cert private key and certificate
##################################################

# Generate RSA Valid Certificate Request for a CA cert
openssl req -new -nodes -newkey rsa:4096 -keyout ca_rsa_pkey.pem -out ca_rsa.csr -subj "/C=CA/O=Wire/CN=ServerCA"
fail_on_error "generating private key (ca_rsa_pkey.pem) and certificate request (ca_rsa.csr)"

# Generate the RSA CA certificate from the request
openssl x509 -req -in ca_rsa.csr -signkey ca_rsa_pkey.pem -out ca_rsa_cert.pem -days 3650
fail_on_error "generating public cert (ca_rsa_cert.pem) from certificate request (ca_rsa.csr)"

# Generate ECDSA Valid Certificate Request for a CA cert
openssl req -new -nodes -newkey ec:<(openssl ecparam -name prime256v1) -keyout ca_ecdsa_pkey.pem -out ca_ecdsa.csr -subj "/C=CA/O=Wire/CN=ServerCA"
fail_on_error "generating private key (ca_ecdsa_pkey.pem) and certificate request (ca_ecdsa.csr)"

# Generate the ECDSA CA certificate from the request
openssl x509 -req -in ca_ecdsa.csr -signkey ca_ecdsa_pkey.pem -out ca_ecdsa_cert.pem -days 3650
fail_on_error "generating public cert (ca_ecdsa_cert.pem) from certificate request (ca_ecdsa.csr)"


####################################################
# Generate the private keys and certificate requests
####################################################

# Generate ECDSA Valid Certificate Request
openssl req -new -nodes -newkey ec:<(openssl ecparam -name prime256v1) -keyout federation_ecdsa_pkey.pem -out federation_ecdsa.csr -subj "/C=CA/O=Wire/CN=Server"
fail_on_error "generating private key (federation_ecdsa_pkey.pem) and certificate request (federation_ecdsa.csr)"

# Generate RSA Valid Certificate Request
openssl req -new -nodes -newkey rsa:4096 -keyout federation_rsa_pkey.pem -out federation_rsa.csr -subj "/C=CA/O=Wire/CN=Server"
fail_on_error "generating private key (federation_rsa_pkey.pem) and certificate request (federation_rsa.csr)"


#########################################
# Generate the certificates from requests
#########################################

openssl x509 -req -in federation_ecdsa.csr -CA ca_ecdsa_cert.pem -CAkey ca_ecdsa_pkey.pem -CAcreateserial -out federation_ecdsa_cert.pem -days 3650 -extfile <(printf "subjectAltName=DNS:Server")
fail_on_error "generating public cert (federation_ecdsa_cert.pem) from certificate request (federation_ecdsa.csr)"

openssl x509 -req -in federation_rsa.csr -CA ca_rsa_cert.pem -CAkey ca_rsa_pkey.pem -CAcreateserial -out federation_rsa_cert.pem -days 3650 -extfile <(printf "subjectAltName=DNS:Server")
fail_on_error "generating public cert (federation_rsa_cert.pem) from certificate request (federation_rsa.csr)"

openssl x509 -req -in federation_rsa.csr -CA ca_rsa_cert.pem -CAkey ca_rsa_pkey.pem -CAcreateserial -out federation_rsa_expired_cert.pem -days -1 -extfile <(printf "subjectAltName=DNS:Server")
fail_on_error "generating public cert (federation_rsa_expired_cert.pem) from certificate request (federation_rsa.csr)"

faketime -f '+10y' openssl x509 -req -in federation_rsa.csr -CA ca_rsa_cert.pem -CAkey ca_rsa_pkey.pem -CAcreateserial -out federation_rsa_notyetvalid_cert.pem -days 3650 -extfile <(printf "subjectAltName=DNS:Server")
fail_on_error "generating public cert (federation_rsa_not_yet_valid_cert.pem) from certificate request (federation_rsa.csr)"

#openssl x509 -req -in federation_rsa.csr -CA ca_rsa_cert.pem -CAkey ca_rsa_pkey.pem -CAcreateserial -out federation_rsa_badsig_cert.pem -days -3650 -badsig -extfile <(printf "subjectAltName=DNS:Server")
#fail_on_error "generating public cert (federation_rsa_badsig_cert.pem) from certificate request (federation_rsa.csr)"
#Note:  Above line is causing openssl 1.1.1f to seg fault, manually mess up the signature instaed
cp federation_rsa_cert.pem federation_rsa_badsig_cert.pem
echo "X" | dd of=federation_rsa_badsig_cert.pem bs=1 seek=1757 count=1 conv=notrunc
fail_on_error "generating public cert (federation_rsa_badsig_cert.pem)"


