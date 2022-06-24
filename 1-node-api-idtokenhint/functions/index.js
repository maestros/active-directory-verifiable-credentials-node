const functions = require("firebase-functions");

// // Create and Deploy Your First Cloud Functions
// // https://firebase.google.com/docs/functions/write-firebase-functions
//
// exports.helloWorld = functions.https.onRequest((request, response) => {
//   functions.logger.info("Hello logs!", {structuredData: true});
//   response.send("Hello from Firebase!");
// });

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// Verifiable Credentials Sample

///////////////////////////////////////////////////////////////////////////////////////
// Node packages
var express = require('express')
var session = require('express-session')
var base64url = require('base64url')
var secureRandom = require('secure-random');
var bodyParser = require('body-parser')
// mod.cjs
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));
const https = require('https')
const url = require('url')
const { SSL_OP_COOKIE_EXCHANGE } = require('constants');
var msal = require('@azure/msal-node');
const fs = require('fs');
const crypto = require('crypto');

var http = require('http');
var path = require('path');

const cors = require('cors');
const { Console } = require('console');
var uuid = require('uuid');

///////////////////////////////////////////////////////////////////////////////////////
// config file can come from command line, env var or the default
var configFile = './config.json';

const config = require( configFile )
if (!config.azTenantId) {
  throw new Error('The config.json file is missing: ' + configFile)
}
module.exports.config = config;

const app = express()
const port = config.port || 8080;

const corsOptions = {
  origin: '*',
  allowedHeaders: ['Access-Control-Allow-Origin', 'Content-Type', 'Authorization', 'Content-Length', 'X-Requested-With', 'Accept'],
  methods: ['GET', 'PUT', 'POST', 'DELETE', 'OPTIONS'],
  optionsSuccessStatus: 200 
};

app.use(cors(corsOptions));

console.log(`MSALCONFIG: https://login.microsoftonline.com/${config.azTenantId}`)
///////////////////////////////////////////////////////////////////////////////////////
// MSAL
var msalConfig = {
  auth: {
      clientId: config.azClientId,
      authority: `https://login.microsoftonline.com/${config.azTenantId}`,
      clientSecret: config.azClientSecret,
  },
  system: {
      loggerOptions: {
          loggerCallback(loglevel, message, containsPii) {
              console.log(message);
          },
          piiLoggingEnabled: false,
          logLevel: msal.LogLevel.Verbose,
      }
  }
};

// if certificateName is specified in config, then we change the MSAL config to use it
if ( config.azCertificateName !== '') {
  const privateKeyData = fs.readFileSync(config.azCertificatePrivateKeyLocation, 'utf8');
  console.log(config.azCertThumbprint);  
  const privateKeyObject = crypto.createPrivateKey({ key: privateKeyData, format: 'pem',    
    passphrase: config.azCertificateName.replace("CN=", "") // the passphrase is the appShortName (see Configure.ps1)    
  });
  msalConfig.auth = {
    clientId: config.azClientId,
    authority: `https://login.microsoftonline.com/${config.azTenantId}`,
    clientCertificate: {
      thumbprint: config.azCertThumbprint,
      privateKey: privateKeyObject.export({ format: 'pem', type: 'pkcs8' })
    }
  };
}

const cca = new msal.ConfidentialClientApplication(msalConfig);
const msalClientCredentialRequest = {
  scopes: ["3db474b9-6a0c-4840-96ac-1fceb342124f/.default"],
  skipCache: false, 
};

module.exports.msalClientCredentialRequest = msalClientCredentialRequest;

// Check if it is an EU tenant and set up the endpoint for it
fetch( `https://login.microsoftonline.com/${config.azTenantId}/v2.0/.well-known/openid-configuration`, { method: 'GET'} )
  .then(res => res.json())
  .then((resp) => {
    console.log( `tenant_region_scope = ${resp.tenant_region_scope}`);
    config.tenant_region_scope = resp.tenant_region_scope;
    config.msIdentityHostName = "https://beta.did.msidentity.com/v1.0/";
    if ( resp.tenant_region_scope == "EU" ) {
      config.msIdentityHostName = "https://beta.eu.did.msidentity.com/v1.0/";
    }
    // Check that the Credential Manifest URL is in the same tenant Region and throw an error if it's not
    if ( !config.CredentialManifest.startsWith(config.msIdentityHostName) ) {
      throw new Error( `Error in config file. CredentialManifest URL configured for wrong tenant region. Should start with: ${config.msIdentityHostName}` );
    }
  }); 
///////////////////////////////////////////////////////////////////////////////////////
// Main Express server function
// Note: You'll want to update port values for your setup.



var parser = bodyParser.urlencoded({ extended: false });

// Serve static files out of the /public directory
app.use(express.static('public'))

// Set up a simple server side session store.
// The session store will briefly cache issuance requests
// to facilitate QR code scanning.
var sessionStore = new session.MemoryStore();
app.use(session({
  secret: 'cookie-secret-key',
  resave: false,
  saveUninitialized: true,
  store: sessionStore
}))

app.use(function (req, res, next) {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "Authorization, Origin, X-Requested-With, Content-Type, Accept");
  next();
});

module.exports.sessionStore = sessionStore;
module.exports.app = app;

function requestTrace( req ) {
  var dateFormatted = new Date().toISOString().replace("T", " ");
  var h1 = '//****************************************************************************';
  console.log( `${h1}\n${dateFormatted}: ${req.method} ${req.protocol}://${req.headers["host"]}${req.originalUrl}` );
  console.log( `Headers:`)
  console.log(req.headers);
}

// echo function so you can test that you can reach your deployment
app.get("/echo",
    function (req, res) {
        requestTrace( req );
        res.status(200).json({
            'date': new Date().toISOString(),
            'api': req.protocol + '://' + req.hostname + req.originalUrl,
            'Host': req.hostname,
            'x-forwarded-for': req.headers['x-forwarded-for'],
            'x-original-host': req.headers['x-original-host']
            });
    }
);

// Serve index.html as the home page
app.get('/', function (req, res) { 
  requestTrace( req );
  res.sendFile('public/index.html', {root: __dirname})
})

// verifier
var parser = bodyParser.urlencoded({ extended: false });

///////////////////////////////////////////////////////////////////////////////////////
// Setup the presentation request payload template
var requestConfigFile =  './presentation_request_config.json';

var presentationConfig = require( requestConfigFile );
presentationConfig.registration.clientName = "Node.js SDK API Verifier";
presentationConfig.authority = config["VerifierAuthority"]
// copy the issuerDID from the settings and fill in the acceptedIssuers part of the payload
// this means only that issuer should be trusted for the requested credentialtype
// this value is an array in the payload, you can trust multiple issuers for the same credentialtype
// very common to accept the test VCs and the Production VCs coming from different verifiable credential services
presentationConfig.presentation.requestedCredentials[0].acceptedIssuers[0] = config["IssuerAuthority"]
var apiKey = uuid.v4();
if ( presentationConfig.callback.headers ) {
  presentationConfig.callback.headers['api-key'] = apiKey;
}

function requestTrace( req ) {
  var dateFormatted = new Date().toISOString().replace("T", " ");
  var h1 = '//****************************************************************************';
  console.log( `${h1}\n${dateFormatted}: ${req.method} ${req.protocol}://${req.headers["host"]}${req.originalUrl}` );
  console.log( `Headers:`)
  console.log(req.headers);
}
/**
 * This method is called from the UI to initiate the presentation of the verifiable credential
 */
app.get('/api/verifier/presentation-request', cors(), async (req, res) => {
  console.log('----> Inside /api/verifier/presentation-request');

  requestTrace( req );
  var id = req.session.id;
  console.log( `Session ID: ${id}` );

  // prep a session state of 0
  sessionStore.get( id, (error, session) => {
    var sessionData = {
      "status" : 0,
      "message": "Waiting for QR code to be scanned"
    };
    if ( session ) {
      session.sessionData = sessionData;
      sessionStore.set( id, session);
    }
  });
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Headers", "X-Requested-With");
  
  // get the Access Token
  var accessToken = "";
  console.log('Getting accessTokenv2')
  try {
    console.log('msalConfig');
    console.log(msalConfig);
    const result = await cca.acquireTokenByClientCredential(msalClientCredentialRequest);
    console.log(result);

    if ( result ) {
      accessToken = result.accessToken;
    }
  } catch (err) {
      console.log( "failed to get access token: " );
      console.log(err);

      res.status(401).json({
        'error': 'Could not acquire credentials to access your Azure Key Vault'
        });  
      return; 
  }
  console.log( `accessToken: ${accessToken}` );
  // modify the callback method to make it easier to debug 
  // with tools like ngrok since the URI changes all the time
  // this way you don't need to modify the callback URL in the payload every time
  // ngrok changes the URI
  presentationConfig.callback.url = `https://us-central1-vc-node-demo.cloudfunctions.net/app/api/verifier/presentation-request-callback`;
  console.log('callback-url: ' + presentationConfig.callback.url);
  presentationConfig.callback.state = id;

  console.log( 'VC Client API Request' );
  var client_api_request_endpoint = `${config.msIdentityHostName}${config.azTenantId}/verifiablecredentials/request`;
  console.log('client_api_request_endpoint: ');
  console.log( client_api_request_endpoint );
  var payload = JSON.stringify(presentationConfig);
  console.log('presentationConfig:');
  console.log( payload );
  const fetchOptions = {
    method: 'POST',
    body: payload,
    headers: {
      'Content-Type': 'application/json',
      'Content-Length': payload.length.toString(),
      'Authorization': `Bearer ${accessToken}`
    }
  };

  console.log('client_api_request_endpoint: ' + client_api_request_endpoint);

  const response = await fetch(client_api_request_endpoint, fetchOptions);
  var resp = await response.json()

  // the response from the VC Request API call is returned to the caller (the UI). It contains the URI to the request which Authenticator can download after
  // it has scanned the QR code. If the payload requested the VC Request service to create the QR code that is returned as well
  // the javascript in the UI will use that QR code to display it on the screen to the user.            
  resp.id = id;                              // add id so browser can pull status
  console.log( 'VC Client API Response' );
  console.log( resp );  
  res.status(200).json(resp);       
})

/**
 * This method is called by the VC Request API when the user scans a QR code and presents a Verifiable Credential to the service
 */
app.post('/api/verifier/presentation-request-callback', parser, async (req, res) => {
  console.log('Inside /api/verifier/presentation-request-callback');
  var body = '';
  req.on('data', function (data) {
    console.log('adding data: ' + data);
    body += data;
  });
  req.on('end', function () {
    console.log('Received presentation-request-callback data');
    requestTrace( req );
    console.log( body );
    if ( req.headers['api-key'] != apiKey ) {
      res.status(401).json({
        'error': 'api-key wrong or missing'
        });
        console.log('error: api-key wrong or missing');
      return; 
    }
    var presentationResponse = JSON.parse(body.toString());
    console.log('presentationResponse');
    console.log(presentationResponse);

    // there are 2 different callbacks. 1 if the QR code is scanned (or deeplink has been followed)
    // Scanning the QR code makes Authenticator download the specific request from the server
    // the request will be deleted from the server immediately.
    // That's why it is so important to capture this callback and relay this to the UI so the UI can hide
    // the QR code to prevent the user from scanning it twice (resulting in an error since the request is already deleted)            
    if ( presentationResponse.code == "request_retrieved" ) {
      sessionStore.get( presentationResponse.state, (error, session) => {
        var cacheData = {
            "status": presentationResponse.code,
            "message": "QR Code is scanned. Waiting for validation..."
        };
        session.sessionData = cacheData;
        sessionStore.set( presentationResponse.state, session, (error) => {
          console.log(error);
          res.send();
        });
      })      
    }
    // the 2nd callback is the result with the verified credential being verified.
    // typically here is where the business logic is written to determine what to do with the result
    // the response in this callback contains the claims from the Verifiable Credential(s) being presented by the user
    // In this case the result is put in the in memory cache which is used by the UI when polling for the state so the UI can be updated.
    if ( presentationResponse.code == "presentation_verified" ) {
      console.log("presentation_verified");
      sessionStore.get(presentationResponse.state, (error, session) => {
        var cacheData = {
            "status": presentationResponse.code,
            "message": "Presentation received",
            "payload": presentationResponse.issuers,
            "subject": presentationResponse.subject,
            "firstName": presentationResponse.issuers[0].claims.firstName,
            "lastName": presentationResponse.issuers[0].claims.lastName,
            "presentationResponse": presentationResponse
        };
        session.sessionData = cacheData;
        sessionStore.set( presentationResponse.state, session, (error) => {
          console.log(error);
          res.send();
        });
      })      
    }
  });  
  res.send()
})
/**
 * this function is called from the UI polling for a response from the AAD VC Service.
 * when a callback is recieved at the presentationCallback service the session will be updated
 * this method will respond with the status so the UI can reflect if the QR code was scanned and with the result of the presentation
 */
app.get('/api/verifier/presentation-response', cors(), async (req, res) => {

      console.log('---> Inside /api/verifier/presentation-response');
      var id = req.query.id;
      requestTrace( req );
      sessionStore.get( id, (error, session) => {
        console.log(error);
        console.log('Session: ' + session);
        if (session){
          console.log(session.sessionData);
        }
        if (session && session.sessionData) {
          console.log(`status: ${session.sessionData.status}, message: ${session.sessionData.message}`);
          if ( session.sessionData.status == "presentation_verified" ) {
            delete session.sessionData.presentationResponse; // browser don't need this
          }
          console.log('Sending session data');
          res.header("Access-Control-Allow-Origin", "*");
          res.header("Access-Control-Allow-Headers", "Authorization, Origin, X-Requested-With, Content-Type, Accept");
          res.status(200).json(session.sessionData);   
          res.send();
          } else {
            console.log('Not sending session data');
            res.header("Access-Control-Allow-Origin", "*");
            res.header("Access-Control-Allow-Headers", "Authorization, Origin, X-Requested-With, Content-Type, Accept");
        //    res.status(200);
            res.send();
          }
      })
})

/**
 * B2C REST API Endpoint for retrieveing the VC presentation response
 * body: The InputClaims from the B2C policy. It will only be one claim named 'id'
 * return: a JSON structure with claims from the VC presented
 */
var parserJson = bodyParser.json();
app.post('/api/verifier/presentation-response-b2c', cors(), parserJson, async (req, res) => {
  console.log('/api/verifier/presentation-response-b2c');
  var id = req.body.id;
  requestTrace( req );
  sessionStore.get( id, (error, store) => {
    console.log(error);
    if (store && store.sessionData && store.sessionData.status == "presentation_verified" ) {
      console.log("Has VC. Will return it to B2C");      
      var claims = store.sessionData.presentationResponse.issuers[0].claims;
      var claimsExtra = {
        'vcType': presentationConfig.presentation.requestedCredentials[0].type,
        'vcIss': store.sessionData.presentationResponse.issuers[0].authority,
        'vcSub': store.sessionData.presentationResponse.subject,
        'vcKey': store.sessionData.presentationResponse.subject.replace("did:ion:", "did.ion.").split(":")[0]
        };        
        var responseBody = { ...claimsExtra, ...claims }; // merge the two structures
        req.session.sessionData = null; 
        console.log( responseBody );
        res.status(200).json( responseBody );   
    } else {
      console.log('Will return 409 to B2C');
      res.status(409).json({
        'version': '1.0.0', 
        'status': 400,
        'userMessage': 'Verifiable Credentials not presented'
        });   
    }
  })
})


// start server
//app.listen(port, () => console.log(`Example issuer app listening on port ${port}!`))

exports.app = functions.https.onRequest(app);