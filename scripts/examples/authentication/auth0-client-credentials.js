var HttpRequestHeader = Java.type('org.parosproxy.paros.network.HttpRequestHeader');
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var URI = Java.type('org.apache.commons.httpclient.URI');
var AuthenticationHelper = Java.type('com.stackhawk.hste.authentication.AuthenticationHelper');


function authenticate(helper, paramsValues, credentials) {
	print("Auth0 Auth...");
	
	//build request header
	var requestUri = new URI(paramsValues.get("issuer"), false);
	var requestMethod = HttpRequestHeader.POST;
	var requestHeader = new HttpRequestHeader(requestMethod, requestUri, HttpHeader.HTTP11);
    requestHeader.setHeader("Content-Type", "application/x-www-form-urlencoded");
    requestHeader.setHeader("Accept", "application/json");
    requestHeader.setHeader("Cache-control", "no-cache");

	//build request body
	var requestBody= "client_id="+credentials.getParam('client_id') + 
	"&client_secret=" + credentials.getParam('client_secret') + 
	"&grant_type=" + paramsValues.get('grant_type') + 
	"&audience=" + paramsValues.get('audience');

	
	// build final post
	var msg = helper.prepareMessage();
	msg.setRequestHeader(requestHeader);
	msg.setRequestBody(requestBody);
	print("MSG RH: " + msg.requestHeader)
	print("MSG RB: " + msg.requestBody)
	requestHeader.contentLength = msg.requestBody.length();
	
	//send message
	helper.sendAndReceive(msg);
	print(msg.responseBody)

	return msg;
}


function getRequiredParamsNames(){
	return ["issuer", "grant_type"];
}

function getOptionalParamsNames(){
	return ["audience"];
}

function getCredentialsParamsNames(){
	return ["client_id", "client_secret"];
}