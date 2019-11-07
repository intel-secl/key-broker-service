#!/bin/bash

# usage:  test.sh

# NOTE: this script is to be modified before use. Following things are necessary:
#Transfer Policy mentioned should be in /opt/kms/repository/keys-transfer-policy
#Usage Policy mentioned should be in /opt/kms/repository/keys-usage-policy
#Pem files should be present.


# if hostname not given, http://127.0.0.1:80 or https://127.0.0.1:443 will be assumed

hostname=${KMS_TEST_URL:-"https://127.0.0.1:2443"}

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
#get_transfer_json() {
    #hello=$1
#    curl $CURL_OPTS -H "Accept: application/json" -H "Session-ID:SW:$1" -H "Accept-Challenge: SW" "$@"
#}
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

#create transfer policy to used by CRUD APIs.
test_createTransferPolicy() {
cat >$tmpdir/createTransferPolicy-request.json <<EOF
{
        "sgx_enclave_issuer_anyof":["kms.intel.com","kms.intel.com"],
        "sgx_enclave_issuer_product_id_anyof":[25, 25],
        "sgx_enclave_issuer_extended_product_id_anyof":[214543, 1111111111111111],
        "sgx_enclave_measurement_anyof":[56, 78],
        "sgx_config_id_svn":11,
        "sgx_enclave_svn_minimum":34,
        "kpt2_issuer_anyof":["kpt.intel.com", "kpt2.intel1.com"],
        "sgx_config_id_anyof":[67,89],
        "tls_client_certificate_issuer_cn_anyof":["intel"],
        "tls_client_certificate_san_allof":["dspg.intel.com", "dcg.intel.com"],
        "attestation_type_anyof":["SGX","KPT2"]
}
EOF

    post_json --data @$tmpdir/createTransferPolicy-request.json  -o $tmpdir/createTransferPolicy-response.json -w "%{http_code}" $hostname/v1/key-transfer-policies >$tmpdir/createTransferPolicy-response.status  2>$tmpdir/createTransferPolicy-debug.log

    if [ -s $tmpdir/createTransferPolicy-response.json ]; then
        jq < $tmpdir/createTransferPolicy-response.json
        transferPolicyID=$(jq -r '.created[0].id' <$tmpdir/createTransferPolicy-response.json)
        if [ -n "$transferPolicyID" ]; then
            echo "Created transfer policy: $transferPolicyID"
            TRANSFER_POLICY=$transferPolicyID
        fi
    fi
}

#create Usage policy to used by CRUD APIs.
test_createUsagePolicy() {
cat >$tmpdir/createUsagePolicy-request.json <<EOF
{
        "not_after":"2019-05-17T22:24:20-08:00",
        "not_before":"2018-05-17T22:24:20-08:00"
}
EOF
#curl -v -k -X POST -u admin:changeit -H "Accept: application/json" -H "Content-Type: application/json" --data @usage_createkey-request.json -o usage_createkey-response.json -w "%{http_code}" https://vault.intel:2443/v1/key-usage-policies >usage_createkey-response.status 2>usage_createkey-debug.log 

    post_json --data @$tmpdir/createUsagePolicy-request.json  -o $tmpdir/createUsagePolicy-response.json -w "%{http_code}" $hostname/v1/key-usage-policies >$tmpdir/createUsagePolicy-response.status  2>$tmpdir/createUsagePolicy-debug.log

    if [ -s $tmpdir/createUsagePolicy-response.json ]; then
        jq < $tmpdir/createUsagePolicy-response.json
        usagePolicyID=$(jq -r '.created[0].id' < $tmpdir/createUsagePolicy-response.json)
        if [ -n "$usagePolicyID" ]; then
            echo "Created usage policy: $usagePolicyID"
            USAGE_POLICY=$usagePolicyID
        fi
    fi
}

# create a key for RSA algorithm
# expected output example:
# {"meta":{},"id":"81caa8e2-cd71-41ce-a84c-0a3a41a20907","cipher_mode":"OFB","algorithm":"RSA","key_length":128,"padding_mode":"None","transfer_policy":"urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization","transfer_link":"http://deucp101.amr.corp.intel.com/v1/keys/81caa8e2-cd71-41ce-a84c-0a3a41a20907/transfer","digest_algorithm":"SHA-256"}
# post-condition:
#   sets the KMS_TEST_KEY_ID variable
test_createRSA_key() {
    cat >$tmpdir/createkeyRSA-request.json <<EOF
{
    "descriptor_uri":"urn:intel:dhsm2:crypto-schema:storage",
    "algorithm":"RSA",
    "key_length":"1024",
    "cipher_mode":"OFB",
    "padding_mode":"None",
    "digest_algorithm":"SHA-256",
    "transfer_policy":"$TRANSFER_POLICY",
    "usage_policy":"$USAGE_POLICY",
    "cka_label":"abcd"
}
EOF

    post_json --data @$tmpdir/createkeyRSA-request.json  -o $tmpdir/createkeyRSA-response.json -w "%{http_code}" $hostname/v1/keys >$tmpdir/createkeyRSA-response.status  2>$tmpdir/createkeyRSA-debug.log
    assert_http_status createkeyRSA-response.status 200 || return 1

    if [ -s $tmpdir/createkeyRSA-response.json ]; then
        jq < $tmpdir/createkeyRSA-response.json
        rsaKey_id=$(jq -r '.id' < $tmpdir/createkeyRSA-response.json)
        if [ -n "$rsaKey_id" ]; then
            echo "Created key id: $rsaKey_id"
            KMS_RSA_TEST_KEY_ID=$rsaKey_id
        fi
    fi
}

# create a key fir algorithm EC
# expected output example:
# {"meta":{},"id":"81caa8e2-cd71-41ce-a84c-0a3a41a20907","cipher_mode":"OFB","algorithm":"EC","key_length":128,"padding_mode":"None","transfer_policy":"urn:intel:trustedcomputing:key-transfer-policy:require-trust-or-authorization","transfer_link":"http://deucp101.amr.corp.intel.com/v1/keys/81caa8e2-cd71-41ce-a84c-0a3a41a20907/transfer","digest_algorithm":"SHA-256"}
# post-condition:
#   sets the KMS_TEST_KEY_ID variable
test_createEC_key() {
    cat >$tmpdir/createkeyEC-request.json <<EOF
{
    "descriptor_uri":"urn:intel:dhsm2:crypto-schema:storage",
    "algorithm":"EC",
    "curve_type":"prime256v1",
    "cipher_mode":"OFB",
    "padding_mode":"None",
    "digest_algorithm":"SHA-256",
    "transfer_policy":"$TRANSFER_POLICY",
    "usage_policy":"$USAGE_POLICY",
    "cka_label":"abcd"
}
EOF

    post_json --data @$tmpdir/createkeyEC-request.json  -o $tmpdir/createkeyEC-response.json -w "%{http_code}" $hostname/v1/keys >$tmpdir/createkeyEC-response.status  2>$tmpdir/createkeyEC-debug.log
    assert_http_status createkeyEC-response.status 200 || return 1

    if [ -s $tmpdir/createkeyEC-response.json ]; then
        jq < $tmpdir/createkeyEC-response.json
        ecKey_id=$(jq -r '.id' < $tmpdir/createkeyEC-response.json)
        if [ -n "$ecKey_id" ]; then
            echo "Created key id: $ecKey_id"
            KMS_EC_TEST_KEY_ID=$ecKey_id
        fi
    fi
}

# usage 2: test_delete_key <url>
# usage 2: KMS_RSA_TEST_KEY_ID=... && test_delete_key
test_RSA_delete_key() {
    local url=$1
    if [ -z "$url" ] && [ -n "$KMS_RSA_TEST_KEY_ID" ]; then
        url=$hostname/v1/keys/$rsaKey_id
    fi
    if [ -z "$url" ]; then
        echo "url parameter or KMS_RSA_TEST_KEY_ID variable missing" >&2
        return 1
    fi
    curl $CURL_OPTS -X DELETE -o $tmpdir/deletekeyRSA-response -w "%{http_code}" $url >$tmpdir/deletekeyRSA-response.status 2>$tmpdir/deletekeyRSA-debug.log
    assert_http_status deletekeyRSA-response.status 204 || return 1

    # check the deleted key is no longer served by kms
    get_json -o $tmpdir/getkeyinfo-deleted-response.json -w "%{http_code}" $hostname/v1/keys/$rsaKey_id >$tmpdir/getkeyinfo-deleted-response.status 2>$tmpdir/getkeyinfo-deleted-debug.log
    assert_http_status getkeyinfo-deleted-response.status 404  || return 1
    # TODO: found a bug while testing this... server returns 400 Bad Request and this content: "com.intel.dcsg.cpg.crypto.key.KeyNotFoundException" instead of a 404 Not Found with no content. This issue is now resolve din version 2.
}

# usage 2: test_delete_key <url>
# usage 2: KMS_EC_TEST_KEY_ID=... && test_delete_key
test_EC_delete_key() {
    local url=$1
    if [ -z "$url" ] && [ -n "$KMS_EC_TEST_KEY_ID" ]; then
        url=$hostname/v1/keys/$ecKey_id
    fi
    if [ -z "$url" ]; then
        echo "url parameter or KMS_EC_TEST_KEY_ID variable missing" >&2
        return 1
    fi
    curl $CURL_OPTS -X DELETE -o $tmpdir/deletekeyEC-response -w "%{http_code}" $url >$tmpdir/deletekeyEC-response.status 2>$tmpdir/deletekeyEC-debug.log
    assert_http_status deletekeyEC-response.status 204 || return 1

    # check the deleted key is no longer served by kms
    get_json -o $tmpdir/getECkeyinfo-deleted-response.json -w "%{http_code}" $hostname/v1/keys/$ecKey_id >$tmpdir/getECkeyinfo-deleted-response.status 2>$tmpdir/getECkeyinfo-deleted-debug.log
    assert_http_status getECkeyinfo-deleted-response.status 404  || return 1
    # TODO: found a bug while testing this... server returns 400 Bad Request and this content: "com.intel.dcsg.cpg.crypto.key.KeyNotFoundException" instead of a 404 Not Found with no content. This issue is now resolve din version 2.
}

# usage 2: test_keyinfo <url>
# usage 2: KMS_RSA_TEST_KEY_ID =... && test_keyinfo
test_RSA_keyinfo() {
    local url=$1
    if [ -z "$url" ] && [ -n "$KMS_RSA_TEST_KEY_ID" ]; then
        url=$hostname/v1/keys/$rsaKey_id
    fi
    if [ -z "$url" ]; then
        echo "url parameter or KMS_RSA_TEST_KEY_ID variable missing" >&2
        return 1
    fi
    get_json -o $tmpdir/getRSAkeyinfo-response.json -w "%{http_code}" $url >$tmpdir/getRSAkeyinfo-response.status 2>$tmpdir/getRSAkeyinfo-debug.log
    assert_http_status getRSAkeyinfo-response.status 200 || return 1
}

# usage 2: test_keyinfo <url>
# usage 2: KMS_EC_TEST_KEY_ID=... && test_keyinfo
test_EC_keyinfo() {
    local url=$1
    if [ -z "$url" ] && [ -n "$KMS_EC_TEST_KEY_ID" ]; then
        url=$hostname/v1/keys/$ecKey_id
    fi
    if [ -z "$url" ]; then
        echo "url parameter or KMS_EC_TEST_KEY_ID variable missing" >&2
        return 1
    fi
    get_json -o $tmpdir/getECkeyinfo-response.json -w "%{http_code}" $url >$tmpdir/getECkeyinfo-response.status 2>$tmpdir/getECkeyinfo-debug.log
    assert_http_status getECkeyinfo-response.status 200 || return 1
}


# usage : test_allKey <url>
test_allKey() {
    local url=$1
    if [ -z "$url" ]; then
        url=$hostname/v1/keys/
    fi
    if [ -z "$url" ]; then
        echo "url parameter variable missing" >&2
        return 1
    fi
    get_json -o $tmpdir/getAllkeyinfo-response.json -w "%{http_code}" $url >$tmpdir/getAllkeyinfo-response.status 2>$tmpdir/getAllkeyinfo-debug.log
    assert_http_status getAllkeyinfo-response.status 200 || return 1
}

# usage 2: test_keyinfo <url>
# usage 2: KMS_RSA_TEST_KEY_ID =... && test_keyinfo
test_RSA_key_Transfer() {
    local url=$1
    if [ -z "$url" ] && [ -n "$KMS_RSA_TEST_KEY_ID" ]; then
        url=$hostname/v1/keys/$rsaKey_id/dhsm2-transfer
    fi
    if [ -z "$url" ]; then
        echo "url parameter or KMS_RSA_TEST_KEY_ID variable missing" >&2
        return 1
    fi
    #dummy session-ID
    x="a65c167c-f160-46d4-b3b8-90b8c080543a"
    get_transfer_json "$x" -o $tmpdir/transferRSAKey-response.json -w "%{http_code}" $url >$tmpdir/transferRSAkeyinfo-response.status 2>$tmpdir/transferRSAkeyinfo-debug.log

echo "$get_transfer_json"
#curl -k -v -X GET -H "Accept: application/json" -H "Accept-Challenge: SW" -H "Session-ID:SW:a65c167c-f160-46d4-b3b8-90b8c080543a" -o $tmpdir/transferRSAKey-response.json -w "%{http_code}" $url >$tmpdir/transferRSAkeyinfo-response.status 2>$tmpdir/transferRSAkeyinfo-debug.log
curl -k -v -X GET -H "Accept: application/json" -H "Accept-Challenge: KPT2, SGX" -H "Session-ID:SW:a65c167c-f160-46d4-b3b8-90b8c080543a" --cert /opt/kms/configuration/certificate.pem --key /opt/kms/configuration/certificate_key.pem -o $tmpdir/transferRSAKey-response.json -w "%{http_code}" $url >$tmpdir/transferRSAkeyinfo-response.status 2>$tmpdir/transferRSAkeyinfo-debug.log

assert_http_status transferRSAkeyinfo-response.status 401 || return 1
    
if [ -s $tmpdir/transferRSAKey-response.json ]; then
    jq < $tmpdir/transferRSAKey-response.json
    session_id=$(jq -r '.challenge' < $tmpdir/transferRSAKey-response.json)
    if [ -n "$session_id" ]; then
	echo "Challenge is: $session_id"
	KMS_RSA_SESSION_ID=$session_id
    fi
fi

#now create a session
    cat >$tmpdir/createRSASession-request.json <<EOF
    {
"challenge_type":"SGX",
"challenge":"$KMS_RSA_SESSION_ID",
"quote":"SW50ZWwtMSAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBbWtEK2t3bGJzbXZ5VVlPQnVWa3kKV0R5Qk54R1FOSnJLVVp1OTdaK2hCRzNPQTg1Zlk2b1ZDZHlvVCtLRG10QUZnVGdZNzZLUmtIVllRSDNIWUZwZQpjNXZOcHRMSk5kNk9WSkNYUjZORlVSMmI3YUhMa3Jlc3F5UE1yQUhOVTE2d3A4NXFkSEFMTmQ3MkVvVVBrVkl0CkhxYUJPbGR4N0o5dnlVRjNicEFXcTRYeFJsYmlLOWl2WXVjaTQvanI0cHBSb3NvNkxabTlJbnptNTN6WXQyQXEKSFVaUSszV2dLK2N6WnlrOHRMR0VON3J0TFo3b3B2VkFhQWlSR1dpVVdBQ3RSd21wQXEyTDVQdVdaa1lkUTdXUQppZ2t4NWMzeDhpQmtlRWgwMjJ6cVlrR09UaDJVZTRVZnJJWXVTcWpMYjJkK2prZlpRMVM0TFFMUVB0TXhOVi9GCnF3SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="
}
EOF
#    post_json --data @$tmpdir/createRSASession-request.json -o $tmpdir/createRSASession-response.json -w "%{http_code}" $hostname/v1/session >$tmpdir/createRSASession-response.status  2>$tmpdir/createRSASession-debug.log
    post_json --data @$tmpdir/createRSASession-request.json --cert /opt/kms/configuration/certificate.pem --key /opt/kms/configuration/certificate_key.pem -o $tmpdir/createRSASession-response.json -w "%{http_code}" $hostname/v1/session >$tmpdir/createRSASession-response.status  2>$tmpdir/createRSASession-debug.log
    assert_http_status createRSASession-response.status 201 || return 1

#Now transfer as session is created
challenge=`echo $KMS_RSA_SESSION_ID== | base64 --decode`
echo $challenge

#curl -k -v -X GET -u admin:changeit -H "Accept: application/json" -H "Accept-Challenge: SW" -H "Session-ID:SW:$challenge" -o $tmpdir/transferRSAKeyPositive-response.json -w "%{http_code}" $url >$tmpdir/transferRSAkeyinfoPositive-response.status 2>$tmpdir/transferRSAkeyinfoPositive-debug.log
curl -v -X GET -H "Accept: application/json" -H "Accept-Challenge:KPT2, SGX" -H "Session-ID:SW:$challenge" --cert /opt/kms/configuration/certificate.pem --key /opt/kms/configuration/certificate_key.pem -o $tmpdir/transferRSAKeyPositive-response.json -w "%{http_code}" $url >$tmpdir/transferRSAkeyinfoPositive-response.status 2>$tmpdir/transferRSAkeyinfoPositive-debug.log

    assert_http_status transferRSAkeyinfoPositive-response.status 200 || return 1
}

# usage 2: test_keyinfo <url>
# usage 2: KMS_EC_TEST_KEY_ID =... && test_keyinfo
test_EC_key_Transfer() {
    local url=$1
    if [ -z "$url" ] && [ -n "$KMS_EC_TEST_KEY_ID" ]; then
        url=$hostname/v1/keys/$ecKey_id/dhsm2-transfer
    fi
    if [ -z "$url" ]; then
        echo "url parameter or KMS_EC_TEST_KEY_ID variable missing" >&2
        return 1
    fi
    #dummy session-ID
    x="a65c167c-f160-46d4-b3b8-90b8c080543a"
    #get_transfer_json "$x" -o $tmpdir/transferRSAKey-response.json -w "%{http_code}" $url >$tmpdir/transferRSAkeyinfo-response.status 2>$tmpdir/transferRSAkeyinfo-debug.log

#echo "$get_transfer_json"
#curl -k -v -X GET -u admin:changeit -H "Accept: application/json" -H "Accept-Challenge: SW" -H "Session-ID:SW:a65c167c-f160-46d4-b3b8-90b8c080543a" -o $tmpdir/transferECKey-response.json -w "%{http_code}" $url >$tmpdir/transferECKeyinfo-response.status 2>$tmpdir/transferECKeyinfo-debug.log
curl -v -X GET -H "Accept: application/json" -H "Accept-Challenge: KPT2, SGX" -H "Session-ID:SW:a65c167c-f160-46d4-b3b8-90b8c080543a" --cert /opt/kms/configuration/certificate.pem --key /opt/kms/configuration/certificate_key.pem -o $tmpdir/transferECKey-response.json -w "%{http_code}" $url >$tmpdir/transferECKeyinfo-response.status 2>$tmpdir/transferECkeyinfo-debug.log

    assert_http_status transferECKeyinfo-response.status 401 || return 1
    
   # echo "trace 2"

if [ -s $tmpdir/transferECKey-response.json ]; then
    jq < $tmpdir/transferECKey-response.json
    session_id=$(jq -r '.challenge' < $tmpdir/transferECKey-response.json)
    if [ -n "$session_id" ]; then
	echo "Challenge is: $session_id"
	KMS_RSA_SESSION_ID=$session_id
    fi
fi

#now create a session
    cat >$tmpdir/createECSession-request.json <<EOF
    {
"challenge_type":"SGX",
"challenge":"$KMS_RSA_SESSION_ID",
"quote":"SW50ZWwtMSAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC0tLS0tQkVHSU4gUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBbWtEK2t3bGJzbXZ5VVlPQnVWa3kKV0R5Qk54R1FOSnJLVVp1OTdaK2hCRzNPQTg1Zlk2b1ZDZHlvVCtLRG10QUZnVGdZNzZLUmtIVllRSDNIWUZwZQpjNXZOcHRMSk5kNk9WSkNYUjZORlVSMmI3YUhMa3Jlc3F5UE1yQUhOVTE2d3A4NXFkSEFMTmQ3MkVvVVBrVkl0CkhxYUJPbGR4N0o5dnlVRjNicEFXcTRYeFJsYmlLOWl2WXVjaTQvanI0cHBSb3NvNkxabTlJbnptNTN6WXQyQXEKSFVaUSszV2dLK2N6WnlrOHRMR0VON3J0TFo3b3B2VkFhQWlSR1dpVVdBQ3RSd21wQXEyTDVQdVdaa1lkUTdXUQppZ2t4NWMzeDhpQmtlRWgwMjJ6cVlrR09UaDJVZTRVZnJJWXVTcWpMYjJkK2prZlpRMVM0TFFMUVB0TXhOVi9GCnF3SURBUUFCCi0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="
}
EOF
    post_json --data @$tmpdir/createECSession-request.json --cert /opt/kms/configuration/certificate.pem --key /opt/kms/configuration/certificate_key.pem -o $tmpdir/createECSession-response.json -w "%{http_code}" $hostname/v1/session >$tmpdir/createECSession-response.status  2>$tmpdir/createECSession-debug.log
    assert_http_status createECSession-response.status 201 || return 1

    #post_json --data @$tmpdir/createRSASession-request.json -o $tmpdir/createRSASession-response.json -w "%{http_code}" $hostname/v1/session >$tmpdir/createRSASession-response.status  2>$tmpdir/createRSASession-debug.log
    #assert_http_status createRSASession-response.status 201 || return 1

#Now transfer as session is created
challenge=`echo $KMS_RSA_SESSION_ID== | base64 --decode`
echo $challenge

#curl -k -v -X GET -u admin:changeit -H "Accept: application/json" -H "Accept-Challenge: SW" -H "Session-ID:SW:$challenge" -o $tmpdir/transferECKeyPositive-response.json -w "%{http_code}" $url >$tmpdir/transferECKeyinfoPositive-response.status 2>$tmpdir/transferECKeyinfoPositive-debug.log
curl -X GET --cert /opt/kms/configuration/certificate.pem --key /opt/kms/configuration/certificate_key.pem -H "Accept: application/json" -H "Accept-Challenge: KPT2, SGX" -H "Session-ID:SW:$challenge" -o $tmpdir/transferECKeyPositive-response.json -w "%{http_code}" $url >$tmpdir/transferECKeyinfoPositive-response.status 2>$tmpdir/transferECKeyinfoPositive-debug.log

    assert_http_status transferECKeyinfoPositive-response.status 200 || return 1
}

# the test plan:
KMS_TEST_PLAN="test_createTransferPolicy test_createUsagePolicy test_version test_createRSA_key test_createEC_key test_RSA_keyinfo test_EC_keyinfo test_RSA_key_Transfer test_EC_key_Transfer test_RSA_delete_key test_EC_delete_key test_allKey"

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
