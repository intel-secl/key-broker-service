
            function TpmIdentityCertificateListViewModel() {
                var self = this;
                //data
                self.tpmIdentityCertificates = ko.observableArray([]);
                self.viewTpmIdentityCertificateRequest = ko.observable(new X509Certificate({}));
                self.registerTpmIdentityCertificateRequest = ko.observable(new X509CertificatePEM({}));
                self.deleteTpmIdentityCertificateRequest = ko.observable(new X509Certificate({}));
                self.searchCriteria = ko.observable(new X509CertificateSearchCriteria());
                // operations
                self.searchTpmIdentityCertificates = function(searchCriteriaItem) {
                    console.log("Endpoint: %s", endpoint);
        //            console.log("Search SAML certificates 1: %O", ko.toJSON(searchCriteriaItem)); //   results in error: InvalidStateError: Failed to read the 'selectionDirection' property from 'HTMLInputElement': The input element's type ('hidden') does not support selection
                    console.log("Search SAML certificates: %O", ko.toJSON(searchCriteriaItem));
        //            console.log("Search SAML certificates 2: %O", searchCriteriaItem);
        //            console.log("Search SAML certificates 3: %s", $.param(ko.toJSON(searchCriteriaItem)));
        //            console.log("Search SAML certificates 4: %s", $.param(searchCriteriaItem)); // id=undefined&role=undefined&algorithm=undefined&SAML certificate_length=undefined&cipher_mode=undefined&padding_mode=undefined&digest_algorithm=undefined&transfer_policy=undefined&limit=undefined&offset=undefined
                    $.ajax({
                        type: "GET",
                        url: endpoint + "/tpm-identity-certificates",
                        headers: {'Accept': 'application/json'},
                        data: $("#searchTpmIdentityCertificatesForm").serialize(), // or we could use ko to serialize searchCriteriaItem $.params(ko.toJSON(searchCriteriaItem))
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
                            self.tpmIdentityCertificates(mappedItems);
                        }
                    });
                };
                self.viewTpmIdentityCertificate = function(viewTpmIdentityCertificateItem) {
                    console.log("View SAML certificate: %O", viewTpmIdentityCertificateItem);
                    if (viewTpmIdentityCertificateItem) {
                        self.viewTpmIdentityCertificateRequest(viewTpmIdentityCertificateItem);
                    }
                };
                self.closeViewTpmIdentityCertificate = function(viewTpmIdentityCertificateItem) {
                    self.viewTpmIdentityCertificateRequest(new X509Certificate({}));
                };
                self.registerTpmIdentityCertificate = function(registerTpmIdentityCertificateItem) {
                    console.log("Register SAML certificate: %O", registerTpmIdentityCertificateItem);
                    $.ajax({
                        type: "POST",
                        url: endpoint + "/tpm-identity-certificates",
                        contentType: "application/x-pem-file",
                        headers: {'Accept': 'application/json'},
                        data: registerTpmIdentityCertificateItem.certificate_pem(), // base64 encoded
                        success: function(data, status, xhr) {
                            console.log("Register SAML certificate response: %O", data);
                            self.searchTpmIdentityCertificates({});
                            //self.tpmIdentityCertificates.push(new X509Certificate(data)); // have to add this and not SAML certificateItem because server ersponse includes SAML certificate id
                            $('#addTpmIdentityCertificateModalDialog').modal('hide');
                        }
                    });

                };
                self.confirmDeleteTpmIdentityCertificate = function(deleteTpmIdentityCertificateItem) {
                    console.log("Confirm delete SAML certificate: %O", deleteTpmIdentityCertificateItem); // deleteTpmIdentityCertificateItem a TpmIdentityCertificate object
                    self.deleteTpmIdentityCertificateRequest(deleteTpmIdentityCertificateItem);
                };
                self.deleteTpmIdentityCertificate = function(deleteTpmIdentityCertificateItem) {
                    console.log("Delete SAML certificate: %O", deleteTpmIdentityCertificateItem); // the deleteTpmIdentityCertificateItem is the form element (don't know why) and .serializeObject returns a TpmIdentityCertificate object
        //            var deleteTpmIdentityCertificateId = $("#deleteTpmIdentityCertificateForm input[name='id']")[0].val();
                    var deleteTpmIdentityCertificateId = deleteTpmIdentityCertificateItem.id();
                    console.log("Delete SAML certificate id: %s", deleteTpmIdentityCertificateId);
                    $.ajax({
                        type: "DELETE",
                        url: endpoint + "/tpm-identity-certificates/" + deleteTpmIdentityCertificateId,
                        success: function(data, status, xhr) {
                            console.log("Delete SAML certificate response: %O", data);
                            self.tpmIdentityCertificates.remove(deleteTpmIdentityCertificateItem);
                            $('#deleteTpmIdentityCertificateModalDialog').modal('hide');
                        }
                    });
                };
            }
