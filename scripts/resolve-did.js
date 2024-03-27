const { UniRegistrar, DIDRegistrationRequestBuilder, UniResolver } = require('@sphereon/did-uni-client');

const did = 'did:web:LovreMitrovic.github.io:did-database:issuer';
const resolver = new UniResolver();

resolver.resolve(did)
    .then(result => console.log(result))
    .catch(error => console.log(error));