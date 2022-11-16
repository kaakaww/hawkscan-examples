var HttpRequestHeader = Java.type('org.parosproxy.paros.network.HttpRequestHeader');
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var URI = Java.type('org.apache.commons.httpclient.URI');
var AuthenticationHelper = Java.type('org.zaproxy.zap.authentication.AuthenticationHelper');


function authenticate(helper, paramsValues, credentials) {
	print("Cognito Auth...");
	
	//build request header
	var requestUri = new URI(paramsValues.get("auth_provider"), false);
	var requestMethod = HttpRequestHeader.POST;
	var requestHeader = new HttpRequestHeader(requestMethod, requestUri, HttpHeader.HTTP11);
    requestHeader.setHeader("X-Amz-Target", "AWSCognitoIdentityProviderService.InitiateAuth");
    requestHeader.setHeader("Content-Type", "application/x-amz-json-1.1");
    requestHeader.setHeader("Accept", "application/json");
    requestHeader.setHeader("Cache-control", "no-cache");

	//build request body
	var requestBody = JSON.stringify({"AuthParameters": {"USERNAME": credentials.getParam('username'), "PASSWORD": credentials.getParam('password'),
    }, "AuthFlow": paramsValues.get('auth_flow'), "ClientId": credentials.getParam('client_id')})

	
	// build final post
	var msg = helper.prepareMessage();
	msg.setRequestHeader(requestHeader);
	msg.setRequestBody(requestBody);
	print("MSG RH: " + msg.requestHeader)
	print("MSG RB: " + msg.requestBody)
	requestHeader.contentLength = msg.requestBody.length();
	
	//send message
	helper.sendAndReceive(msg);
    var rep = msg.getResponseBody().toString();
    print(rep)
    

	return msg;
}


function getRequiredParamsNames(){
	return ["auth_provider", "auth_flow"];
}

function getOptionalParamsNames(){
	return [];
}

function getCredentialsParamsNames(){
	return ["username", "password", "client_id"];
}
