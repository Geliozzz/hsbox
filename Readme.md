# What is it

It is like a secure box for a file. The program generate random AES key and encrypt the file. AES key encrypt by public key for decryption using private key. The public key you can give everybody, private key only for you.

## How it works

* Take recipient public key
* Encrypt a file by public key
* Send file
-- The Recipient
* Get file
* Decrypt it by private key

## CLI

Heart shaped box CLI

Usage: hsbox

Commands:  
  put       - Put file in a secure box  
  get       - Get file from a secure box  
  generate  - Get pair of public and private keys in PEM forman  
  help      - Print this message or the help of the given subcommand(s)  
  
Options:  
  -h, --help  Print help information  
hsbox put ~/Documents/cmake.pdf box.hsb assets/public.pem  

### Examples

hsbox generate temp/  
hsbox get box.hsb temp/ temp/private.pem  
hsbox put ~/Documents/temp.pdf box.hsb temp/public.pem  

### Key generation

#### by openssl

openssl genrsa -des3 -out private.pem 2048
openssl rsa -in private.pem -outform PEM -pubout -out public.pem

In this case you will be able to use password with private key

#### by the prorgamm

hsbox generate {existing directory}
