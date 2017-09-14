RSA Keys are generated with openssl:

// Generate private key
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:2048

// Convert private key to .der (format for libtomcrypt)
openssl rsa  -outform der -in private_key.pem -out private_key.der

// Extract public key .pem
openssl rsa -pubout -in private_key.pem -out public_key.pem

// Extract public key .der (format for libtomcrypt)
openssl rsa -pubout -in private_key.pem -outform DER -out public_key.der
