#!/bin/bash

generate_signatures() {
  echo "Entering "`pwd`
  FILE=content.json
  if [[ -f "$FILE" ]]; then
    echo
    echo "Content-Length: "`wc -c content.json | awk '{print $1}'`
    echo "Content-MD5: "`md5sum content.json | awk '{print $1}'`
    echo "ETag: "`md5sum input.txt | awk '{print $1}'`
    echo
    echo "BODY ================>"
    cat content.json
  fi

  echo
  SIGNATURE_RSA_SHA256=`openssl dgst -sha256 -sign ../../test.private.pem input.txt | base64 --wrap=0`
  SIGNATURE_RSA_SHA384=`openssl dgst -sha384 -sign ../../test.private.pem input.txt | base64 --wrap=0`
  SIGNATURE_RSA_SHA512=`openssl dgst -sha512 -sign ../../test.private.pem input.txt | base64 --wrap=0`
  SIGNATURE_RSAPSS_SHA256=`openssl dgst -sha256 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sign ../../test.private.pem input.txt | base64 --wrap=0`
  SIGNATURE_RSAPSS_SHA384=`openssl dgst -sha384 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sign ../../test.private.pem input.txt | base64 --wrap=0`
  SIGNATURE_RSAPSS_SHA512=`openssl dgst -sha512 -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1 -sign ../../test.private.pem input.txt | base64 --wrap=0`

  dirname=`pwd`
  KEY_ID="${dirname##*/}"
  CREATED=`grep "(created)" input.txt | awk -F': ' '{print $2}'`
  EXPIRES=`grep "(expires)" input.txt | awk -F': ' '{print $2}'`
  HEADERS=`awk -F': ' '{print $1}' input.txt | sed -z 's/\n/ /g' | sed -e 's/ $//'`

  echo "keyId=\"$KEY_ID\", algorithm=\"rsa-sha256\", created=$CREATED, expires=$EXPIRES, headers=\"$HEADERS\", signature=\"$SIGNATURE_RSA_SHA256\"" > signature.rsa-sha256
  echo "Generated RSA: sha-256"
  echo "keyId=\"$KEY_ID\", algorithm=\"rsa-sha384\", created=$CREATED, expires=$EXPIRES, headers=\"$HEADERS\", signature=\"$SIGNATURE_RSA_SHA384\"" > signature.rsa-sha384
  echo "Generated RSA: sha-384"
  echo "keyId=\"$KEY_ID\", algorithm=\"rsa-sha512\", created=$CREATED, expires=$EXPIRES, headers=\"$HEADERS\", signature=\"$SIGNATURE_RSA_SHA512\"" > signature.rsa-sha512
  echo "Generated RSA: sha-512"
  echo "keyId=\"$KEY_ID-rsapss-256\", created=$CREATED, expires=$EXPIRES, headers=\"$HEADERS\", signature=\"$SIGNATURE_RSAPSS_SHA256\"" > signature.rsapss-sha256
  echo "keyId=\"$KEY_ID-rsapss-384\", created=$CREATED, expires=$EXPIRES, headers=\"$HEADERS\", signature=\"$SIGNATURE_RSAPSS_SHA384\"" > signature.rsapss-sha384
  echo "keyId=\"$KEY_ID-rsapss-512\", created=$CREATED, expires=$EXPIRES, headers=\"$HEADERS\", signature=\"$SIGNATURE_RSAPSS_SHA512\"" > signature.rsapss-sha512
}

cd full
generate_signatures
cd ../minimal
generate_signatures
