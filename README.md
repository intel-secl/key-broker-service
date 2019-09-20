# Intel<sup>®</sup> Security Libraries for Data Center  - Key Broker Service
#### The Intel<sup>®</sup> SecL - DC Key Broker Service(KBS) component performs key distribution using platform trust to authorize key transfers. The KBS verifies the host's attestation from the Verification Service, verifies all digital signatures, and retains final control over whether the decryption key is issued. If the server's attestation meets the policy requirements, the KBS issues a decryption key itself wrapped using the AIK-derived binding key from the host that was attested, cryptographically ensuring that only the attested host can decrypt the requested image

## Key features
- Provides and retains encryption/decryption keys for virtual machine images / docker images
- The Key Broker Service connects to a back-end 3rd Party KMIP-compliant key management service, like OpenStack Barbican, for key creation and vaulting services

## System Requirements
- RHEL 7.5/7.6
- Epel 7 Repo
- Proxy settings if applicable

## Software requirements
- git
- maven (v3.3.1)
- ant (v1.9.10 or more)

# Step By Step Build Instructions
## Install required shell commands
Please make sure that you have the right `http proxy` settings if you are behind a proxy
```shell
export HTTP_PROXY=http://<proxy>:<port>
export HTTPS_PROXY=https://<proxy>:<port>
```
### Install tools from `yum`
```shell
$ sudo yum install -y wget git zip unzip ant makeself
```

## Direct dependencies
Following repositories needs to be build before building this repository,

| Name                       | Repo URL                                                 |
| -------------------------- | -------------------------------------------------------- |
| common-java                | https://github.com/intel-secl/common-java                |
| lib-saml                   | https://github.com/intel-secl/lib-saml                   |

## Build Verification Service

- Git clone the `Key Broker Service`
- Run scripts to build the `Key Broker Service`

```shell
$ git clone https://github.com/intel-secl/key-broker-service.git
$ cd key-broker-service
$ ant ready clean -Dmtwilson3=true
$ cd maven/
$ mvn -DskipTests=true clean install -U
$ cd ../features/
$ mvn clean -DskipTests=true -Ddependency.locations.enabled=false -Drelease -Dmtwilson3=true install -U
$ cd ../features/kms-saml-client-jaxrs2/
$ mvn clean -DskipTests=true -Ddependency.locations.enabled=false -Drelease site:site install -U
$ cd ../../packages/
$ mvn clean install -DskipTests=true -Dmtwilson3=true -U
```

# Links
 - Use [Automated Build Steps](https://01.org/intel-secl/documentation/build-installation-scripts) to build all repositories in one go, this will also provide provision to install prerequisites and would handle order and version of dependent repositories.

***Note:** Automated script would install a specific version of the build tools, which might be different than the one you are currently using*
 - [Product Documentation](https://01.org/intel-secl/documentation/intel%C2%AE-secl-dc-product-guide)

