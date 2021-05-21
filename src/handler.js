const jwk = require('jsonwebtoken');
const jwkToPem = require('jwk-to-pem');
const request = require('request');
const authenticate = require("./service").authenticate;
const config = require('../config/dev');

var issuers = process.env.ISSUERS;

module.exports.authorizer = async (event, context, callback) => {

    var authentication = await authenticate(event);
    console.log(authentication);
    console.log({ message: 'Authenticated', data: authentication });

    if (authentication.effect == 'deny' || authentication.effect == 'unauthorized' || authentication.message != '') {
        var is_valid = authentication.effect;
    }else{

        if ((authentication.groups.indexOf("administration") !== -1) || (authentication.groups.indexOf("credit_management") !== -1) || (authentication.groups.indexOf("general_user") !== -1)) {
            var is_valid = "allow";
        }else{
            var is_valid = "deny";
        }
    }
    switch (is_valid) {
      case "allow":
        callback(null, generatePolicy("user", "Allow", event.methodArn, authentication))
        break
      case "deny":
        callback(null, generatePolicy("user", "Deny", event.methodArn, authentication))
        break
      case "unauthorized":
        callback("Unauthorized") // Return a 401 Unauthorized response
        break
      default:
        callback("Error: Invalid token")
    }
  }
  // Help function to generate an IAM policy
  var generatePolicy = function(principalId, effect, resource, authentication) {
    var authResponse = {}
    authResponse.principalId = principalId
    if (effect && resource) {
      var policyDocument = {}
      policyDocument.Version = "2012-10-17"
      policyDocument.Statement = []
      var statementOne = {}
      statementOne.Action = "execute-api:Invoke"
      statementOne.Effect = effect
      statementOne.Resource = resource
      policyDocument.Statement[0] = statementOne
      authResponse.policyDocument = policyDocument
    }
    // Optional output with custom properties of the String, Number or Boolean type.
    authResponse.context = {
        "is_valid" : effect
    };
    return authResponse
  }