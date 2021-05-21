const verifyToken = require("./verifyToken").verifyToken;
var aws = require('aws-sdk');
const Cognito = new aws.CognitoIdentityServiceProvider();

module.exports.authenticate = async (event,context) => {
    if (!event.headers) {
        return {
            groups: '',
            profileId: '',
            principalId : '',
            effect : 'deny',
            message : 'Headers are missing'
        };
        throw new UnauthorizedError();
    }
    const authorizationToken = event.headers['Authorization'];
    if (!authorizationToken) {
        console.log('No authorization token --error -2');
        return {
            groups: '',
            profileId: '',
            principalId : '',
            effect : 'deny',
            message : 'Authorization token is missing'
        };
    }
    if (authorizationToken.startsWith('Bearer ') && authorizationToken.length > 'Bearer '.length) {
        const token = authorizationToken.substr('Bearer '.length);
        const verifyResult = await verifyToken(token,context);
        if (!verifyResult.isValid || !verifyResult.claims) {
            console.log('=================== SERVICE 004');
            return {
                groups: '',
                profileId: '',
                principalId : '',
                effect : 'unauthorized',
                message : 'Invalid Token'
            };
        }
        let claims = verifyResult.claims;
        if (claims['token_use'] === 'access') {
            claims = await claimsByAccessToken(token);
        }
        const username = claims['cognito:username'];
        const groupsAttr = claims['cognito:groups'];
        return {
            groups: groupsAttr,
            profileId: claims['cognito:username'],
            principalId : claims['identities'][0].userId,
            effect : 'allow',
            message : 'Valid Token'
        };
    }
};

const claimsByAccessToken = async (AccessToken) => {
    const idToken = await Cognito.getUser({ AccessToken }).promise()
        .catch((error) => {
            throw new UnauthorizedError();
        });
    return idToken.UserAttributes.reduce((acc, { Name, Value }) => {
        acc[Name] = Value;
        return acc;
    }, {});
};