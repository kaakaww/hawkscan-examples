var HttpRequestHeader = Java.type('org.parosproxy.paros.network.HttpRequestHeader');
var HttpHeader = Java.type('org.parosproxy.paros.network.HttpHeader');
var URI = Java.type('org.apache.commons.httpclient.URI');
var AuthenticationHelper = Java.type('org.zaproxy.zap.authentication.AuthenticationHelper');


function authenticate(helper, paramsValues, credentials) {
	print("Firebase Auth...");


    //Build request Header
    var requestUri = new URI(paramsValues.get("url"), false);
    var requestMethod = HttpRequestHeader.POST;
    var requestHeader = new HttpRequestHeader(requestMethod, requestUri, HttpHeader.HTTP11);
    requestHeader.setHeader("Content-Type", "application/x-www-form-urlencoded");
    requestHeader.setHeader("Accept", "application/json");
    requestHeader.setHeader("Cache-control", "no-cache");
        
    // Build Request Body
    var requestBody= "key="+credentials.getParam('key')+
    "&email=" + credentials.getParam('email') + 
    "&password=" + credentials.getParam('password');

    //Build Final POST Message
	var msg = helper.prepareMessage();
	msg.setRequestHeader(requestHeader);
    msg.setRequestBody(requestBody);
    print("MSG RH: " + msg.requestHeader)
	print("MSG RB: " + msg.requestBody)
    requestHeader.contentLength = msg.requestBody.length();

    //Send Message
	helper.sendAndReceive(msg);

	return msg;
}

function getRequiredParamsNames(){
	return ["url"];
}

function getOptionalParamsNames(){
	return [];
}


function getCredentialsParamsNames(){
	return ["email", "password", "key"];
}
