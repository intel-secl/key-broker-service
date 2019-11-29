#!/bin/bash

# initial setup steps for kms

# ensure that our commands can be found
export PATH=$KMS_BIN:$PATH

# the master password is required
# if already user provided we assume user will also provide later for restarts
# otherwise, we generate and store the password

if [ -z "$KMS_PASSWORD" ] && [ ! -f $KMS_CONFIGURATION/.kms_password ]; then
    touch $KMS_CONFIGURATION/.kms_password
    chown $KMS_USERNAME:$KMS_USERNAME $KMS_CONFIGURATION/.kms_password
    chmod 600 $KMS_CONFIGURATION/.kms_password
    kms generate-password > $KMS_CONFIGURATION/.kms_password
fi

kms config mtwilson.extensions.fileIncludeFilter.contains "${MTWILSON_EXTENSIONS_FILEINCLUDEFILTER_CONTAINS:-mtwilson,kms,jersey-media-multipart,jersey-common}" >/dev/null
kms config mtwilson.extensions.packageIncludeFilter.startsWith "${MTWILSON_EXTENSIONS_PACKAGEINCLUDEFILTER_STARTSWITH:-com.intel,org.glassfish.jersey.media.multipart,org.glassfish.jersey.filter}" >/dev/null

# crypto
kms config password.vault.file $KMS_CONFIGURATION/password-vault.jck >/dev/null
kms config password.vault.type JCEKS >/dev/null
kms config notary.keystore.file $KMS_CONFIGURATION/notary.p12 >/dev/null
kms config notary.keystore.type PKCS12 >/dev/null
kms config envelope.keystore.file $KMS_CONFIGURATION/envelope.p12 >/dev/null
kms config envelope.keystore.type PKCS12 >/dev/null
kms config storage.keystore.file $KMS_CONFIGURATION/storage.jck >/dev/null
kms config storage.keystore.type JCEKS >/dev/null
kms config mtwilson.saml.certificates.file $KMS_CONFIGURATION/saml.p12 >/dev/null
kms config mtwilson.saml.keystore.type PKCS12 >/dev/null
kms config mtwilson.tpm.identity.certificates.file $KMS_CONFIGURATION/tpm.identity.p12 >/dev/null
kms config mtwilson.tpm.identity.keystore.type PKCS12 >/dev/null
kms config javax.net.ssl.keyStore $KMS_CONFIGURATION/keystore.p12 >/dev/null
kms config javax.net.ssl.keyStoreType PKCS12 >/dev/null

kms config mtwilson.api.url $MTWILSON_API_URL >/dev/null

# dashboard
kms config mtwilson.navbar.buttons kms-keys,mtwilson-configuration-settings-ws-v2,mtwilson-core-html5 >/dev/null
kms config mtwilson.navbar.hometab keys >/dev/null

#path to configuration file
kms config dhsm2.cacertfile.path /etc/skc/credential-service/cecs.d/ssl/CA/cacert.pem >/dev/null

#TLS private key length.
kms config jetty.tls.key.length 3072 >/dev/null

if [ -n "$CMS_BASE_URL" ]; then
	kms config cms.base.url "$CMS_BASE_URL" >/dev/null
fi
kms config "cms.tls.cert.sha384" "$CMS_TLS_CERT_SHA384" >/dev/null
	
if [ -n "$AAS_API_URL" ]; then
	kms config aas.api.url "$AAS_API_URL" >/dev/null
fi

if [ -n "$USERNAME" ]; then
	kms config kms.admin.username $USERNAME >/dev/null
fi

if [ -n "$PASSWORD" ]; then
	kms config kms.admin.password $PASSWORD >/dev/null
fi

if [ -n "$KMS_PORT_HTTP" ]; then
    kms config jetty.port $KMS_PORT_HTTP >/dev/null
fi

if [ -n "$KMS_PORT_HTTPS" ]; then
    kms config jetty.secure.port $KMS_PORT_HTTPS >/dev/null
fi

if [ -n "$KMS_TLS_CERT_IP" ]; then
    kms config jetty.tls.cert.ip $KMS_TLS_CERT_IP >/dev/null
fi

if [ -n "$KMS_TLS_CERT_DNS" ]; then
    kms config jetty.tls.cert.dns $KMS_TLS_CERT_DNS >/dev/null
fi

if [ -n "$KEY_MANAGER_PROVIDER" ]; then
    kms config key.manager.provider $KEY_MANAGER_PROVIDER >/dev/null
fi

if [ -n "$KMIP_ENCODER" ]; then
    kms config kmip.encoder $KMIP_ENCODER >/dev/null
fi

if [ -n "$KMIP_DECODER" ]; then
    kms config kmip.decoder $KMIP_DECODER >/dev/null
fi

if [ -n "$KMIP_TRANSPORTLAYER" ]; then
    kms config kmip.transportLayer $KMIP_TRANSPORTLAYER >/dev/null
fi

if [ -n "$KMIP_ENDPOINT" ]; then
    kms config kmip.endpoint $KMIP_ENDPOINT >/dev/null
fi

if [ -n "$BARBICAN_PROJECT_ID" ]; then
    kms config barbican.project.id $BARBICAN_PROJECT_ID >/dev/null
fi

if [ -n "$BARBICAN_ENDPOINT_URL" ]; then
    kms config barbican.endpoint.url $BARBICAN_ENDPOINT_URL >/dev/null
fi

if [ -n "$BARBICAN_KEYSTONE_PUBLIC_ENDPOINT" ]; then
    kms config barbican.keystone.public.endpoint $BARBICAN_KEYSTONE_PUBLIC_ENDPOINT >/dev/null
fi

if [ -n "$BARBICAN_TENANTNAME" ]; then
    kms config barbican.tenantname $BARBICAN_TENANTNAME >/dev/null
fi

if [ -n "$BARBICAN_USERNAME" ]; then
    kms config barbican.username $BARBICAN_USERNAME >/dev/null
fi

if [ -n "$BARBICAN_PASSWORD" ]; then
    kms config barbican.password $BARBICAN_PASSWORD >/dev/null
fi

if [ -n "$ENDPOINT_URL" ]; then
    kms config endpoint.url $ENDPOINT_URL >/dev/null
fi

if [ -n "$REGISTRY_ENDPOINT" ]; then
    kms config registry.endpoint.url $REGISTRY_ENDPOINT >/dev/null
fi

if [ -n "$REGISTRY_TLS_CERTIFICATE_DIGEST" ]; then
    kms config registry.tls.policy.certificate.sha384 $REGISTRY_TLS_CERTIFICATE_DIGEST >/dev/null
fi

if [ -n "$REGISTRY_USERNAME" ]; then
    kms config registry.login.basic.username $REGISTRY_USERNAME >/dev/null
fi

if [ -n "$REGISTRY_PWD" ]; then
    kms config registry.login.basic.password $REGISTRY_PWD >/dev/null
fi

kms setup

# temporary fix for bug #5008
echo >> $KMS_CONFIGURATION/extensions.cache
echo org.glassfish.jersey.media.multipart.MultiPartFeature >> $KMS_CONFIGURATION/extensions.cache
