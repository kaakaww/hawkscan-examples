var JSONObject = Java.type('net.sf.json.JSONObject');
var ScriptVars = Java.type('org.zaproxy.zap.extension.script.ScriptVars');
var HtmlParameter = Java.type('org.parosproxy.paros.network.HtmlParameter');
var COOKIE_TYPE   = org.parosproxy.paros.network.HtmlParameter.Type.cookie;

// Extract the script web session information from the Http Message and store in the ScriptBasedSession
function extractWebSession(sessionWrapper) {

    // get response convert from bytes
    var respJObj = JSONObject.fromObject(sessionWrapper.getHttpMessage().getResponseBody().toString())
    var idToken = respJObj.getString("idToken")
    sessionWrapper.getSession().setValue("idToken", idToken);
}

// Clear any tokens or elements that can link the HttpMessage provided via the sessionWrapper parameter to the WebSession.
function clearWebSessionIdentifiers(sessionWrapper) {
    
}

// Modify the message so its Request Header/Body matches the given web session
function processMessageToMatchSession(sessionWrapper) {
	var idToken = sessionWrapper.getSession().getValue("idToken");
	if (idToken === null) {
		print('JS mgmt script: no token');
		return;
	}
	var cookie = new HtmlParameter(COOKIE_TYPE, "idToken", idToken);
	// add the saved authentication token as a cookie
	var msg = sessionWrapper.getHttpMessage();
	var cookies = msg.getRequestHeader().getCookieParams();
	cookies.add(cookie);
	msg.getRequestHeader().setCookieParams(cookies);
}

function getRequiredParamsNames() {
	return [];
}

function getOptionalParamsNames() {
	return [];
}
