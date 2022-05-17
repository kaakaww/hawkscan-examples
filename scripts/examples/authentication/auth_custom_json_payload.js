//Example script for authenticating to an endpoint that requires a POST containing a custom json payload
//In stackhawk.yml, the standard use of app.authentication.usernamePassword with type: JSON constructs a JSON payload of this format: {"username": "username_value", "password": "password_value"}
//This script can be modified to construct a custom JSON string to send credentials in when the standard format above will not work with the target application
//See https://github.com/kaakaww/hawkscan-examples/blob/main/configs/authentication/stackhawk-auth-json-script.yml for the corresponding yml configs
//To use this script with HawkScan, populate authentication.script (with param login_url and credentials username and password) and hawkAddOn.script (include language: JAVASCRIPT) in stackhawk.yml

var HttpRequestHeader = Java.type('org.parosproxy.paros.network.HttpRequestHeader');
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var URI = Java.type('org.apache.commons.httpclient.URI');
var LogManager = Java.type('org.apache.log4j.LogManager');
var logger = LogManager.getLogger("auth_custom_json_payload");

function authenticate(helper, paramsValues, credentials) {
	logger.info("Authenticating with custom JSON request payload...");
	
	//build request header
	var requestUri = new URI(paramsValues.get("login_url"), false);
	var requestMethod = HttpRequestHeader.POST;
	var requestHeader = new HttpRequestHeader(requestMethod, requestUri, HttpHeader.HTTP11);
	requestHeader.setHeader("Content-Type", "application/json");
    requestHeader.setHeader("Accept", "application/json");

	//build request body
	//resulting json format: {"user":{"username": "username_value", "password": "password_value"}}

	var requestBody = JSON.stringify({"user":{"username": credentials.getParam('username'), "password": credentials.getParam('password')}});

	// build final post
	var msg = helper.prepareMessage();
	msg.setRequestHeader(requestHeader);
	msg.setRequestBody(requestBody);
	logger.info("MSG RH: " + msg.requestHeader)
	logger.info("MSG RB: " + msg.requestBody)
	requestHeader.contentLength = msg.requestBody.length();
	
	//send message
	helper.sendAndReceive(msg);
	logger.info(msg.responseBody)

	return msg;
}

function getRequiredParamsNames(){
	return ["login_url"];
}

function getCredentialsParamsNames(){
	return ["username", "password"];
}

function getOptionalParamsNames(){
	return [];
}