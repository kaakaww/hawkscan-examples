var HttpRequestHeader = Java.type('org.parosproxy.paros.network.HttpRequestHeader');
var HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
var URI = Java.type('org.apache.commons.httpclient.URI');
var AuthenticationHelper = Java.type('org.zaproxy.zap.authentication.AuthenticationHelper');
var Base64 = Java.type("java.util.Base64");
var String = Java.type("java.lang.String");

function authenticate(helper, paramsValues, credentials) {
    print("Okta grant_type=password...");

    // set login path and http
    var requestUri = new URI(paramsValues.get("issuer"), false);
    var requestMethod = HttpRequestHeader.POST;
    var requestHeader = new HttpRequestHeader(requestMethod, requestUri, HttpHeader.HTTP11);

    //build static request headers
    requestHeader.setHeader("Content-Type", "application/x-www-form-urlencoded");
    requestHeader.setHeader("Accept", "application/json");
    requestHeader.setHeader("Cache-control", "no-cache");

    // encode client id / secret
    var basicAuthString = base64Encode((credentials.getParam('client_id') + ':' + credentials.getParam('client_secret')));

    // set the Basic Auth Header
    requestHeader.setHeader("Authorization", "Basic " + basicAuthString);

    //build request body
    var requestBody = "grant_type=" + paramsValues.get('grant_type') +
        "&username=" + credentials.getParam('username') +
        "&password=" + credentials.getParam('password') +
        "&scope=" + paramsValues.get('scope');

    // build final post
    var msg = helper.prepareMessage();
    msg.setRequestHeader(requestHeader);
    msg.setRequestBody(requestBody);
    print("MSG request header: " + msg.requestHeader)
    print("MSG request body: " + msg.requestBody)
    requestHeader.contentLength = msg.requestBody.length();

    //send message
    helper.sendAndReceive(msg);

    return msg;
}

function base64Encode(originalInput) {
    var inputString = String.valueOf(originalInput);
    return Base64.getEncoder().encodeToString(inputString.getBytes());
}

function getRequiredParamsNames(){
    return ["issuer", "grant_type", "scope"];
}

function getOptionalParamsNames(){
    return [""];
}

function getCredentialsParamsNames(){
    return ["client_id", "client_secret", "username", "password"];
}

