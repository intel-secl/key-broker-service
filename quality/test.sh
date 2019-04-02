#!/bin/bash

# usage:  test.sh

# NOTE: this script does NOT assume access to the KMS host; it tests only via APIs 
#        so you need to create the admin user before running this script.


# if hostname not given, http://127.0.0.1:80 or https://127.0.0.1:443 will be assumed

hostname=${KMS_TEST_URL:-"https://127.0.0.1"}

# to customize, export the correct values before running the script
username=${KMS_TEST_USERNAME:-admin}
password=${KMS_TEST_PASSWORD:-changeit}


echo "Test URL: $hostname"

mkdir -p /tmp/test/kms

tmpdir=$(mktemp -d -p /tmp/test/kms)

# assertions
assert_http_status() {
    local filename=$1
    local expected_status=$2
    local actual_status=$(cat $tmpdir/$filename)
    if [ "$expected_status" = "$actual_status" ]; then
        return 0
    fi
    echo "expected http status code $expected_status but actual http status code is $actual_status"
    return 1
}

# useful shortcuts
CURL_OPTS="-v --insecure -u $username:$password"

get_json() {
    curl $CURL_OPTS -H "Accept: application/json" "$@"
}
post_json() {
    curl $CURL_OPTS -H "Content-Type: application/json" -H "Accept: application/json" "$@"
}
get_xml() {
    curl $CURL_OPTS -H "Accept: application/xml" "$@"
}
post_xml() {
    curl $CURL_OPTS -H "Content-Type: application/xml" -H "Accept: application/xml" "$@"
}


# get version 
# expected output example:
# {"version":"3.2-SNAPSHOT","branch":"${git.branch}","timestamp":"2018-08-07T23:47:58.904+0000"}
test_version() {
    get_json -o $tmpdir/version-response.json -w "%{http_code}" $hostname/v1/version >$tmpdir/version-response.status 2>$tmpdir/version-debug.log
    assert_http_status version-response.status 200 || return 1
    if [ -s $tmpdir/version-response.json ]; then
        jq < $tmpdir/version-response.json
    fi
}

# called by test_register_admin_pubkey when it needs the admin_userid
test_list_users() {
    get_json -o $tmpdir/userlist-response.json -w "%{http_code}" $hostname/v1/users >$tmpdir/userlist-response.status 2>$tmpdir/userlist-debug.log
    assert_http_status userlist-response.status 200 || return 1
    if [ -s $tmpdir/userlist-response.json ]; then
        jq < $tmpdir/userlist-response.json
    fi
}

# $KPL_KEY_SERVER_URL/v1/users/$USER_ID/transfer-key
test_register_admin_pubkey() {
    # get the admin userid (precondition: must run test_list_users first)
    admin_userid=
    if [ -s $tmpdir/userlist-response.json ]; then
        admin_userid=$(jq -r '.users | map(select(.username=="admin")) | .[].id' < $tmpdir/userlist-response.json)
    fi
    if [ -z "$admin_userid" ]; then
        echo "Cannot find admin user id, call test_list_users first" >&2
        return 1
    fi
    url="$hostname/v1/users/$admin_userid/transfer-key"
    # create the key if not already created
    if [ ! -f $tmpdir/admin-privatekey.pem ]; then
        openssl genrsa 2048 > $tmpdir/admin-privatekey.pem
        openssl rsa -pubout -in $tmpdir/admin-privatekey.pem -out $tmpdir/admin-publickey.pem
        #openssl pkcs8 -topk8 -inform pem -outform pem -in $tmpdir/admin-privatekey.pem -out $tmpdir/admin-privatekey.pem.pkcs8 -nocrypt
    fi
    # register the key
    curl $CURL_OPTS -X PUT -H "Content-Type: application/x-pem-file" --data-binary @$tmpdir/admin-publickey.pem -o $tmpdir/putadmintransferkey-response.json -w "%{http_code}" $url >$tmpdir/putadmintransferkey-response.status 2>$tmpdir/putadmintransferkey-debug.log   
    assert_http_status putadmintransferkey-response.status 204 || return 1
    # expect 204 no content on success 
}

# create a key
# expected output example:
# {"meta":{},"id":"81caa8e2-cd71-41ce-a84c-0a3a41a20907","cipher_mode":"OFB","algorithm":"AES","key_length":128,"padding_mode":"None","transfer_policy":"urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization","transfer_link":"http://deucp101.amr.corp.intel.com/v1/keys/81caa8e2-cd71-41ce-a84c-0a3a41a20907/transfer","digest_algorithm":"SHA-256"}
# post-condition:
#   sets the KMS_TEST_KEY_ID variable
test_create_key() {
    cat >$tmpdir/createkey-request.json <<EOF
{
    "algorithm":"AES",
    "key_length":"128",
    "cipher_mode":"OFB",
    "padding_mode":"None",
    "digest_algorithm":"SHA-256",
    "transfer_policy":"urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization"
}
EOF

    post_json --data @$tmpdir/createkey-request.json  -o $tmpdir/createkey-response.json -w "%{http_code}" $hostname/v1/keys >$tmpdir/createkey-response.status  2>$tmpdir/createkey-debug.log
    assert_http_status createkey-response.status 200 || return 1

    if [ -s $tmpdir/createkey-response.json ]; then
        jq < $tmpdir/createkey-response.json
        key_id=$(jq -r '.id' < $tmpdir/createkey-response.json)
        if [ -n "$key_id" ]; then
            echo "Created key id: $key_id"
            KMS_TEST_KEY_ID=$key_id
        fi
    fi
}

# usage 2: test_transfer_key_by_admin <url>
# usage 2: KMS_TEST_KEY_ID=... && test_transfer_key_by_admin
test_transfer_key_by_admin() {
    local url=$1
    if [ -z "$url" ] && [ -n "$KMS_TEST_KEY_ID" ]; then
        url=$hostname/v1/keys/$key_id/transfer
    fi
    if [ -z "$url" ]; then
        echo "url parameter or KMS_TEST_KEY_ID variable missing" >&2
        return 1
    fi
    curl $CURL_OPTS -X POST -H "Content-Type: text/plain" -H "Accept: application/x-pem-file" -o $tmpdir/transferkey-response.pem -w "%{http_code}" $url >$tmpdir/transferkey-response.status 2>$tmpdir/transferkey-debug.log
    assert_http_status transferkey-response.status 200 || return 1
    if [ -s $tmpdir/transferkey-response.pem ]; then
        cat $tmpdir/transferkey-response.pem 
    fi
}


# usage 2: test_delete_key <url>
# usage 2: KMS_TEST_KEY_ID=... && test_delete_key
test_delete_key() {
    local url=$1
    if [ -z "$url" ] && [ -n "$KMS_TEST_KEY_ID" ]; then
        url=$hostname/v1/keys/$key_id
    fi
    if [ -z "$url" ]; then
        echo "url parameter or KMS_TEST_KEY_ID variable missing" >&2
        return 1
    fi
    curl $CURL_OPTS -X DELETE -o $tmpdir/deletekey-response -w "%{http_code}" $url >$tmpdir/deletekey-response.status 2>$tmpdir/deletekey-debug.log
    assert_http_status deletekey-response.status 204 || return 1

    # check the deleted key is no longer served by kms
    get_json -o $tmpdir/getkeyinfo-deleted-response.json -w "%{http_code}" $hostname/v1/keys/$key_id >$tmpdir/getkeyinfo-deleted-response.status 2>$tmpdir/getkeyinfo-deleted-debug.log
    assert_http_status getkeyinfo-deleted-response.status 400  || return 1
    # TODO: found a bug while testing this... server returns 400 Bad Request and this content: "com.intel.dcsg.cpg.crypto.key.KeyNotFoundException" instead of a 404 Not Found with no content. 
}

# usage 2: test_keyinfo <url>
# usage 2: KMS_TEST_KEY_ID=... && test_keyinfo
test_keyinfo() {
    local url=$1
    if [ -z "$url" ] && [ -n "$KMS_TEST_KEY_ID" ]; then
        url=$hostname/v1/keys/$key_id
    fi
    if [ -z "$url" ]; then
        echo "url parameter or KMS_TEST_KEY_ID variable missing" >&2
        return 1
    fi
    get_json -o $tmpdir/getkeyinfo-response.json -w "%{http_code}" $url >$tmpdir/getkeyinfo-response.status 2>$tmpdir/getkeyinfo-debug.log
    assert_http_status getkeyinfo-response.status 200 || return 1
}

# the test plan:
KMS_TEST_PLAN="test_version test_list_users test_register_admin_pubkey test_create_key test_keyinfo test_transfer_key_by_admin test_delete_key"

status=
for testname in $KMS_TEST_PLAN
do
    echo "Test NEXT: $testname"
    eval $testname
    status=$?
    if [ $status -ne 0 ]; then
        echo "Test FAIL: $testname"
        break;
    fi
    echo "Test OK: $testname"
done

if [ $status -eq 0 ]; then
    echo "Test complete: No errors"
fi

echo "Test directory: $tmpdir"


# cleanup
#rm -rf $tmpdir
