            function X509CertificatePEM(data) {
                this.certificate_pem = ko.observable(data.certificate_pem);
            }

            function X509Certificate(data) {
                this.id = ko.observable(data.id);
                this.certificate = ko.observable(data.certificate); // base64-encoded certificate
                this.certificate_pem = ko.observable(data.certificate_pem); // base64-encoded certificate with PEM banners
                this.sha1 = ko.observable(data.sha1);
                this.sha256 = ko.observable(data.sha256);
                this.subject = ko.observable(data.subject);
                this.issuer = ko.observable(data.issuer);
                this.notBefore = ko.observable(data.notBefore);
                this.notAfter = ko.observable(data.notAfter);
                this.algorithm = ko.observable(data.algorithm);
                this.key_length = ko.observable(data.key_length);
                this.cipher_mode = ko.observable(data.cipher_mode);
                this.padding_mode = ko.observable(data.padding_mode);
                this.digest_algorithm = ko.observable(data.digest_algorithm);
                this.transfer_policy = ko.observable(data.transfer_policy);
                this.meta = ko.observable(data.meta);
            }

            function X509CertificateSearchCriteria() {
                this.id = ko.observable();
                this.subjectEqualTo = ko.observable();
                this.subjectContains = ko.observable();
                this.issuerEqualTo = ko.observable();
                this.isserContains = ko.observable();
                this.validOn = ko.observable();
                this.validBefore = ko.observable();
                this.validAfter = ko.observable();
                this.sha1 = ko.observable();
                this.sha256 = ko.observable();
                this.algorithm = ko.observable();
                this.key_length = ko.observable();
                this.cipher_mode = ko.observable();
                this.padding_mode = ko.observable();
                this.digest_algorithm = ko.observable();
                this.transfer_policy = ko.observable();
                this.filter = ko.observable();
                this.limit = ko.observable();
                this.offset = ko.observable();
            }
