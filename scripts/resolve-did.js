const { UniRegistrar, DIDRegistrationRequestBuilder, UniResolver } = require('@sphereon/did-uni-client');

//const did = 'did:web:LovreMitrovic.github.io:did-database:issuer';
const did = 'did:jwk:eyJhbGciOiJFUzI1NksiLCJ1c2UiOiJzaWciLCJrdHkiOiJFQyIsImNydiI6InNlY3AyNTZrMSIsIngiOiJ3TTJQeUpCNjJBTzg5b2VjemZienZtVXQtWEpxOEtnYU9yRmI1SkFIeGljIiwieSI6ImQ3cENJY2tvVmNkUThiOWFJSzZvUFFWSkZFTWhjcVVtNW95dUo2V01IQkEifQ#0';
const resolver = new UniResolver();

resolver.resolve(did)
    .then(result => console.log(JSON.stringify(result, null, 2)))
    .catch(error => console.log(error));