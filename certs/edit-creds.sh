#!/bin/bash
./gen-creds.sh
source secrets.txt 
cd ../amazon-freertos/demos/include
envsubst <aws_clientcredential.h.in >aws_clientcredential.h
envsubst <aws_clientcredential_keys.h.in >aws_clientcredential_keys.h
