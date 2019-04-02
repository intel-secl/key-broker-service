
            function SamlCertificateListViewModel() {
                var self = this;
                //data
                self.samlCertificates = ko.observableArray([]);
                self.viewSamlCertificateRequest = ko.observable(new X509Certificate({}));
                self.registerSamlCertificateRequest = ko.observable(new X509CertificatePEM({}));
                self.deleteSamlCertificateRequest = ko.observable(new X509Certificate({}));
                self.searchCriteria = ko.observable(new X509CertificateSearchCriteria());
                // operations
                self.searchSamlCertificates = function(searchCriteriaItem) {
                    console.log("Endpoint: %s", endpoint);
        //            console.log("Search SAML certificates 1: %O", ko.toJSON(searchCriteriaItem)); //   results in error: InvalidStateError: Failed to read the 'selectionDirection' property from 'HTMLInputElement': The input element's type ('hidden') does not support selection
                    console.log("Search SAML certificates: %O", ko.toJSON(searchCriteriaItem));
        //            console.log("Search SAML certificates 2: %O", searchCriteriaItem);
        //            console.log("Search SAML certificates 3: %s", $.param(ko.toJSON(searchCriteriaItem)));
        //            console.log("Search SAML certificates 4: %s", $.param(searchCriteriaItem)); // id=undefined&role=undefined&algorithm=undefined&SAML certificate_length=undefined&cipher_mode=undefined&padding_mode=undefined&digest_algorithm=undefined&transfer_policy=undefined&limit=undefined&offset=undefined
                    $.ajax({
                        type: "GET",
                        url: endpoint + "/saml-certificates",
                        headers: {'Accept': 'application/json'},
                        data: $("#searchSamlCertificatesForm").serialize(), // or we could use ko to serialize searchCriteriaItem $.params(ko.toJSON(searchCriteriaItem))
                        success: function(data, status, xhr) {
                            console.log("Search results: %O", data);
                            /*
                             * Example:
                             * {"search_results":[{"algorithm":"AES","SAML certificate_length":128,"id":"3787f629-1827-411e-866e-ce87e37f805a"},{"algorithm":"AES","SAML certificate_length":128,"id":"dd552684-8238-4c4c-baba-c5e7467d3604"}]}
                             */
                            /*
                             // clear any prior search results
                             while(self.SAML certificates.length>0) { self.SAML certificates.pop(); }
                             // add new results
                             for(var i=0; i<data.search_results.length; i++) {
                             self.SAML certificates.push(new X509Certificate(data.search_results[i]));
                             }
                             */
                            var mappedItems = $.map(data.certificates, function(item) {
                                return new X509Certificate(item);
                            });
                            self.samlCertificates(mappedItems);
                        }
                    });
                };
                self.viewSamlCertificate = function(viewSamlCertificateItem) {
                    console.log("View SAML certificate: %O", viewSamlCertificateItem);
                    if (viewSamlCertificateItem) {
                        self.viewSamlCertificateRequest(viewSamlCertificateItem);
                    }
                };
                self.closeViewSamlCertificate = function(viewSamlCertificateItem) {
                    self.viewSamlCertificateRequest(new X509Certificate({}));
                };
                self.registerSamlCertificate = function(registerSamlCertificateItem) {
                    console.log("Register SAML certificate: %O", registerSamlCertificateItem);
                    $.ajax({
                        type: "POST",
                        url: endpoint + "/saml-certificates",
                        contentType: "application/x-pem-file",
                        headers: {'Accept': 'application/json'},
                        data: registerSamlCertificateItem.certificate_pem(), // base64 encoded
                        success: function(data, status, xhr) {
                            console.log("Register SAML certificate response: %O", data);
                            self.searchSamlCertificates({});
                            //self.samlCertificates.push(new X509Certificate(data)); // have to add this and not SAML certificateItem because server ersponse includes SAML certificate id
                            $('#addSamlCertificateModalDialog').modal('hide');
                        }
                    });

                };
                self.confirmDeleteSamlCertificate = function(deleteSamlCertificateItem) {
                    console.log("Confirm delete SAML certificate: %O", deleteSamlCertificateItem); // deleteSamlCertificateItem a SamlCertificate object
                    self.deleteSamlCertificateRequest(deleteSamlCertificateItem);
                };
                self.deleteSamlCertificate = function(deleteSamlCertificateItem) {
                    console.log("Delete SAML certificate: %O", deleteSamlCertificateItem); // the deleteSamlCertificateItem is the form element (don't know why) and .serializeObject returns a SamlCertificate object
        //            var deleteSamlCertificateId = $("#deleteSamlCertificateForm input[name='id']")[0].val();
                    var deleteSamlCertificateId = deleteSamlCertificateItem.id();
                    console.log("Delete SAML certificate id: %s", deleteSamlCertificateId);
                    $.ajax({
                        type: "DELETE",
                        url: endpoint + "/saml-certificates/" + deleteSamlCertificateId,
                        success: function(data, status, xhr) {
                            console.log("Delete SAML certificate response: %O", data);
                            self.samlCertificates.remove(deleteSamlCertificateItem);
                            $('#deleteSamlCertificateModalDialog').modal('hide');
                        }
                    });
                };
            }
