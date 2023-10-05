#!/bin/bash
# call this script with an email address (valid or not).
# like:
# ./makecert.sh zwh2698@timerd.me
mkdir -p ./certs
rm ./certs/*
#echo "make server cert"
#openssl req -new -nodes -x509 -out certs/server.pem -keyout certs/server.key -days 3650 -subj "/C=DE/ST=NRW/L=Earth/O=Cosmos Company/OU=IT/CN=www.timerd.me/emailAddress=$1"
#echo "make client cert"
#openssl req -new -nodes -x509 -out certs/client.pem -keyout certs/client.key -days 3650 -subj "/C=DE/ST=NRW/L=Earth/O=Cosmos Company/OU=IT/CN=www.timerd.me/emailAddress=$1"


echo "make CA cert"
openssl genrsa -out certs/root.key 4096
openssl req -new -x509 -days 5340 -key certs/root.key -out certs/root.crt

# server 
echo "make server cert"
openssl genrsa -out certs/server.key 4096
openssl req -new -key certs/server.key -out certs/server.csr
openssl x509 -req -days 3650 -CA certs/root.crt -CAkey certs/root.key -CAcreateserial -in certs/server.csr  -out certs/server.crt

#client 
echo "make client cert"
openssl genrsa -out certs/client.key 4096
openssl req -new -key certs/client.key -out certs/client.csr
openssl x509 -req -days 3650 -CA certs/root.crt -CAkey certs/root.key -CAcreateserial -in certs/client.csr  -out certs/client.crt