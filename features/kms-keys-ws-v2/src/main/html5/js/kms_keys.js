
            function Key(data) {
                this.id = ko.observable(data.id);
        //        this.role = ko.observable(data.role);
                this.algorithm = ko.observable(data.algorithm);
                this.key_length = ko.observable(data.key_length);
                this.cipher_mode = ko.observable(data.cipher_mode);
                this.padding_mode = ko.observable(data.padding_mode);
                this.digest_algorithm = ko.observable(data.digest_algorithm);
                this.transfer_policy = ko.observable(data.transfer_policy);
            }
            
            /* in the first draft, user pastes the PEM content with the wrapped key and that's what we send; in later drafts we can inspect the PEM content to look at the headers and we can use form fields to let the user specify algorithm, key length,e tc. if it's not in the headers and then we would insert these attributes */
            function ExistingPemKey(data) {
                this.key_pem = ko.observable(data.key_pem);
                /*
                this.algorithm = ko.observable(data.algorithm);
                this.key_length = ko.observable(data.key_length);
                this.cipher_mode = ko.observable(data.cipher_mode);
                this.padding_mode = ko.observable(data.padding_mode);
                this.digest_algorithm = ko.observable(data.digest_algorithm);
                this.transfer_policy = ko.observable(data.transfer_policy);
                */
            }
            
            function KeySearchCriteria() {
                this.id = ko.observable();
                this.name = ko.observable();
                this.role = ko.observable();
                this.algorithm = ko.observable();
                this.key_length = ko.observable();
                this.cipher_mode = ko.observable();
                this.padding_mode = ko.observable();
                this.digest_algorithm = ko.observable();
                this.transfer_policy = ko.observable();
                this.limit = ko.observable();
                this.offset = ko.observable();
            }

            function KeyListViewModel() {
                var self = this;
                //data
                self.keys = ko.observableArray([]);
                self.viewKeyRequest = ko.observable(new Key({}));
                self.createKeyRequest = ko.observable(new Key({}));
                self.registerKeyRequest = ko.observable(new ExistingPemKey({}));
                self.deleteKeyRequest = ko.observable(new Key({}));
                self.searchCriteria = ko.observable(new KeySearchCriteria());
                // operations
                self.searchKeys = function(searchCriteriaItem) {
                    console.log("Endpoint: %s", endpoint);
        //            console.log("Search keys 1: %O", ko.toJSON(searchCriteriaItem)); //   results in error: InvalidStateError: Failed to read the 'selectionDirection' property from 'HTMLInputElement': The input element's type ('hidden') does not support selection
                    console.log("Search keys: %O", ko.toJSON(searchCriteriaItem));
        //            console.log("Search keys 2: %O", searchCriteriaItem);
        //            console.log("Search keys 3: %s", $.param(ko.toJSON(searchCriteriaItem)));
        //            console.log("Search keys 4: %s", $.param(searchCriteriaItem)); // id=undefined&role=undefined&algorithm=undefined&key_length=undefined&cipher_mode=undefined&padding_mode=undefined&digest_algorithm=undefined&transfer_policy=undefined&limit=undefined&offset=undefined
                    $.ajax({
                        type: "GET",
                        url: endpoint + "/keys",
                        //accept: "application/json",
                        headers: {'Accept': 'application/json'},
                        data: $("#searchKeysForm").serialize(), // or we could use ko to serialize searchCriteriaItem $.params(ko.toJSON(searchCriteriaItem))
                        success: function(responseJsonContent, status, xhr) {
                            console.log("Search results: %O", responseJsonContent);
                            /*
                             * Example:
                             * {"data":[{"algorithm":"AES","key_length":128,"id":"3787f629-1827-411e-866e-ce87e37f805a"},{"algorithm":"AES","key_length":128,"id":"dd552684-8238-4c4c-baba-c5e7467d3604"}]}
                             */
                            /*
                             // clear any prior search results
                             while(self.keys.length>0) { self.keys.pop(); }
                             // add new results
                             for(var i=0; i<responseJsonContent.data.length; i++) {
                             self.keys.push(new Key(responseJsonContent.data[i]));
                             }
                             */
                            var mappedItems = $.map(responseJsonContent.keys, function(item) {
                                return new Key(item);
                            });
                            self.keys(mappedItems);
                        }
                    });
                };
                self.viewKey = function(viewKeyItem) {
                    console.log("View key: %O", viewKeyItem);
                    if (viewKeyItem) {
                        self.viewKeyRequest(viewKeyItem);
                    }
                };
                self.closeViewKey = function(viewKeyItem) {
                    self.viewKeyRequest(new Key({}));
                };
                self.createKey = function(createKeyItem) {
                    console.log("Create key: %O", createKeyItem);
                    $.ajax({
                        type: "POST",
                        url: endpoint + "/keys",
                        contentType: "application/json",
                        headers: {'Accept': 'application/json'},
                        data: ko.toJSON(createKeyItem), //$.toJSON($("#createKeyForm").serializeObject()), // could also use JSON.stringify but it only works on newer browsers
                        success: function(responseJsonContent, status, xhr) {
                            console.log("Create key response: %O", responseJsonContent);
                            self.keys.push(new Key(responseJsonContent)); // have to add this and not keyItem because server ersponse includes key id
                            $('#addKeyModalDialog').modal('hide');
                        }
                    });

                };
                self.registerKey = function(registerKeyItem) {
                    console.log("Register key: %O", registerKeyItem);
                    $.ajax({
                        type: "POST",
                        url: endpoint + "/keys",
                        contentType: "application/x-pem-file",
                        headers: {'Accept': 'application/json'},
                        data: registerKeyItem.key_pem,
                        success: function(responseJsonContent, status, xhr) {
                            console.log("Register key response: %O", responseJsonContent);
                            self.keys.push(new Key(responseJsonContent)); // have to add this and not keyItem because server ersponse includes key id
                        }
                    });

                };
                self.confirmDeleteKey = function(deleteKeyItem) {
                    console.log("Confirm delete key: %O", deleteKeyItem); // deleteKeyItem a Key object
                    self.deleteKeyRequest(deleteKeyItem);
                };
                self.deleteKey = function(deleteKeyItem) {
                    console.log("Delete key: %O", deleteKeyItem); // the deleteKeyItem is the form element (don't know why) and .serializeObject returns a Key object
        //            var deleteKeyId = $("#deleteKeyForm input[name='id']")[0].val();
                    var deleteKeyId = deleteKeyItem.id();
                    console.log("Delete key id: %s", deleteKeyId);
                    $.ajax({
                        type: "DELETE",
                        url: endpoint + "/keys/" + deleteKeyId,
                        success: function(data, status, xhr) {
                            console.log("Delete key response: %O", data);
                            self.keys.remove(deleteKeyItem);
                            $('#deleteKeyModalDialog').modal('hide');
                        }
                    });
                };
            }
