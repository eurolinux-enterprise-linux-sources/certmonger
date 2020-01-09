#!/bin/sh -e

cd "$tmpdir"

source "$srcdir"/functions
initnssdb "$tmpdir"

grep -v ^validity_period $CERTMONGER_CONFIG_DIR/certmonger.conf > \
	$tmpdir/certmonger.conf
cat >> $tmpdir/certmonger.conf << EOF
[selfsign]
validity_period = 46129s
EOF

function append() {
	cat >> $1 <<- EOF
	subject=CN=Babs Jensen
	hostname=localhost,localhost.localdomain
	email=root@localhost,root@localhost.localdomain
	principal=root@EXAMPLE.COM,root@FOO.EXAMPLE.COM
	ku=111
	eku=id-kp-clientAuth,id-kp-emailProtection
	EOF
}

function setupca() {
	cat > ca.self <<- EOF
	id=self_signer
	ca_is_default=0
	ca_type=INTERNAL:SELF
	ca_internal_serial=04
	ca_internal_issue_time=40271
	EOF
}

for size in 512 1024 1536 2048 3072 4096 ; do
	# Build a self-signed certificate.
	run_certutil -d "$tmpdir" -S -g $size -n keyi$size \
		-s "cn=T$size" -c "cn=T$size" \
		-x -t u
	# Export the certificate and key.
	pk12util -d "$tmpdir" -o $size.p12 -W "" -n "keyi$size"
	openssl pkcs12 -in $size.p12 -passin pass: -out key.$size -nodes 2>&1
	# Use that NSS key.
	cat > entry.$size <<- EOF
	key_storage_type=NSSDB
	key_storage_location=$tmpdir
	key_nickname=keyi$size
	EOF
	append entry.$size
	$toolsdir/csrgen entry.$size > csr.nss.$size
	setupca
	$toolsdir/submit ca.self entry.$size > cert.nss.$size
	# Use that OpenSSL key.
	cat > entry.$size <<- EOF
	key_storage_type=FILE
	key_storage_location=$tmpdir/key.$size
	EOF
	append entry.$size
	$toolsdir/csrgen entry.$size > csr.openssl.$size
	setupca
	$toolsdir/submit ca.self entry.$size > cert.openssl.$size
	# Now compare them.
	if ! cmp cert.nss.$size cert.openssl.$size ; then
		echo Certificates differ:
		cat cert.nss.$size cert.openssl.$size
		exit 1
	else
		echo $size OK.
	fi
done
echo Test complete.
