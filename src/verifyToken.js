const config = require('../config/dev');
var atob = require('atob');
const axios = require('axios');
var jwkToPem = require('jwk-to-pem');
const request = require('request');
var issuers = process.env.ISSUERS;
var jwt = require('jsonwebtoken');

module.exports.verifyToken = async (token) => {
    let result;

    try {
        const tokenSections = token.split('.');
        if (tokenSections.length < 3) {
            throw new Error('Requested token is invalid');
        }
        const { iss } = JSON.parse(atob(tokenSections[1]));
        if(issuers !== iss ){
            throw new Error('Unsupported issuer');
        }
        const keys = await getPublicKeys(iss);
        const { kid } = JSON.parse(atob(tokenSections[0]));
        const key = keys[kid];
        if (key === undefined) {
            throw new Error('Token made for unknown kid');
        }
        const claims = jwt.verify(token, key.pem);
        result = { claims, isValid: true }
    } catch (error) {
        result = { error: 'Token InValid', isValid: false };
    }
    return result;
}

const cacheKeys = {};

const getPublicKeys = async(issuer) => {
    if (!cacheKeys[issuer]) {
        const url = `${issuer}/.well-known/jwks.json`;
        const publicKeys = await axios.get(url).then(({ data }) => data);
        cacheKeys[issuer] = publicKeys.keys.reduce((agg, current) => {
                const pem = jwkToPem({...current, kty: 'RSA' });
                agg[current.kid] = { instance: current, pem };
                return agg;
            }, {});
    }
    return cacheKeys[issuer];
};