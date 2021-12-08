var JSONObject = Java.type('net.sf.json.JSONObject');

// Extract the script web session information from the Http Message and store in the ScriptBasedSession
function extractWebSession(sessionWrapper) {

    // get response convert from bytes
    var respJObj = JSONObject.fromObject(sessionWrapper.getHttpMessage().getResponseBody().toString())
    var token = respJObj.getString("access_token")
    sessionWrapper.getSession().setValue("access_token", token);
	print('JS mgmt script: got token ' + token);
}

// Clear any tokens or elements that can link the HttpMessage provided via the sessionWrapper parameter to the WebSession.
function clearWebSessionIdentifiers(sessionWrapper) {
}

// Modify the message so its Request Header/Body matches the given web session
function processMessageToMatchSession(sessionWrapper) {
	var token = sessionWrapper.getSession().getValue("access_token");
	if (token === null) {
		print('JS mgmt script: no token');
		return;
	}
	sessionWrapper.getHttpMessage().getRequestHeader().setHeader("Authorization", "Bearer " + token);
}

function getRequiredParamsNames() {
	return [];
}

function getOptionalParamsNames() {
	return [];
}
