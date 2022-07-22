/**
 * This authentication script works like the internal ZAP PostBasedAuthentication methods.
 * PostBasedAuthentication methods however do not handle the nuances found in many login flows.
 * This script should be modified to handle any missing steps in an automated login scenario.
 */

/** TEMPLATE BEGIN **/
/** Use this boilerplate code in all auth scripts.
 * NOTE: This script requires hawkscan version 2.5.1 or higher to support the getHawkConf() function.
 * **/

/** Import Java classes required for many authentication functions **/
const URLEncoder = Java.type("java.net.URLEncoder");
const URI = Java.type("org.apache.commons.httpclient.URI");
const LogManager = Java.type("org.apache.log4j.LogManager");

const ScriptVars = Java.type("org.zaproxy.zap.extension.script.ScriptVars");
const AuthenticationHelper = Java.type("org.zaproxy.zap.authentication.AuthenticationHelper");
const ExtensionAntiCSRF = Java.type("org.zaproxy.zap.extension.anticsrf.ExtensionAntiCSRF");
const Control = Java.type("org.parosproxy.paros.control.Control");

const HttpHeader = Java.type("org.parosproxy.paros.network.HttpHeader");
const HttpRequestHeader = Java.type("org.parosproxy.paros.network.HttpRequestHeader");

/** Create logger and helper init functions **/
const logger = LogManager.getLogger("custom-form-auth");
let loggingEnabled = false;

// log if enabled
const log = (str) => {
  if (loggingEnabled) {
    logger.info(str)
  }
}

// initialize logging based on parameters from hawk config
const initLogging = (paramsValues) => {
  const loggingParam = paramsValues.get("logging");
  if (loggingParam != null && loggingParam === "true") {
    loggingEnabled = true;
  }
}

/** Reference to the configured hawkscan conf file as a Javascript Object **/
const getHawkConf = () => {
  return JSON.parse(ScriptVars.getGlobalVar("hawkConf"));
}
const hawkConf = getHawkConf();

/** Helper functions **/
// build a URL from supplied params and hawkscan conf's app.host
const paramUrl = (paramsValues, paramName) => {
  return `${hawkConf["app"]["host"]}${paramsValues.get(paramName)}`
}

// build a form-urlencoded string from a Javascript Object
const buildForm = (obj) => {
  let str = "";
  let i = 0;
  for (const key in obj) {
    if (i > 0) {
      str += "&";
    }
    str += `${urlEncode(key)}=${urlEncode(obj[key])}`;
    i++;
  }
  return str;
}

// Url encode a string
const urlEncode = (str) => {
  return URLEncoder.encode(str, "UTF-8");
}

// List of credential names from the configured hawkscan conf
const credentialNames = () => {
  let names = [];
  for (const name in hawkConf["app"]["authentication"]["script"]["credentials"]) {
    names.push(name);
  }
  return names;
}

// Add all credentials to the form Object
const addCredentials = (formObj, credentials) => {
  credentialNames().forEach((name) => {
    formObj[name] = credentials.getParam(name);
  });
}

/** Reference to the ExtensionCsrf AddOn for csrf parsing utilities **/
const extCsrf = Control.getSingleton()
  .getExtensionLoader()
  .getExtension(ExtensionAntiCSRF.class);

/**
 * Make a GET request like a browser would following redirects and accumulating cookies into the "jar"
 * The returned object will contain and array of HttpMessage's in chronological order of each redirect.
 * The HttpMessage contains the requestHeaders, requestBody, responseHeader, and responseBody.
 * **/
const getRequestBrowserLike = (helper, url, jar) => {
  if (jar == null) {
    jar = {cookies: {}, messages: []};
  }

  let requestUri = new URI(url, false);
  let requestHeader = new HttpRequestHeader(HttpRequestHeader.GET, requestUri, HttpHeader.HTTP11);

  let msg = helper.prepareMessage();
  msg.setRequestHeader(requestHeader);

  // Make the HTTP request
  helper.sendAndReceive(msg);

  log(`req/resp: ${logMsg(msg)}`)
  msg.responseHeader.getHttpCookies().forEach((cookie) => {
    if (cookie.name in jar.cookies) {
      jar.cookies[cookie.name].push(cookie);
    } else {
      jar.cookies[cookie.name] = [cookie];
    }
  });

  jar.messages.push(msg);
  const locationHdr = msg.responseHeader.getHeader("Location");
  if (locationHdr != null) {
    return getRequestBrowserLike(helper, locationHdr, jar);
  } else {
    return jar;
  }

}

const jsonMsg = (msg) => {
  return {
    requestHeader: msg.requestHeader.toString(),
    requestBody: msg.requestBody.toString(),
    responseHeader: msg.responseHeader.toString(),
    responseBody: msg.responseBody.toString()
  }
}

const logMsg = (msg) => {
  return `${msg.requestHeader}\r\n\r\n${msg.requestBody}\r\n---\r\n${msg.responseHeader}\r\n\r\n${msg.responseBody}`;
}

/** TEMPLATE END **/

/**
 *
 * @param helper AuthenticationHelper to create new HttpMessages
 * @param paramsValues Map<String, String> of parameter values passed in.
 * See getRequiredParamsNames and getRequiredParamsNames functions below
 * @param credentials Credentials holder. See getCredentialsParamsNames function below
 * @returns HttpMessage containing response from the form authentication POST
 */
function authenticate(helper, paramsValues, credentials) {
  initLogging(paramsValues);
  log("Authenticating with custom script...");

  // Create GET request to the login form page to gather csrf tokesn
  let url = paramUrl(paramsValues, "loginPagePath");

  let requestUri = new URI(url, false);
  let requestHeader = new HttpRequestHeader(HttpRequestHeader.GET, requestUri, HttpHeader.HTTP11);

  let msg = helper.prepareMessage();
  msg.setRequestHeader(requestHeader);

  // Make the HTTP request
  helper.sendAndReceive(msg);

  log(`req/resp1: ${logMsg(msg)}`)

  // Add login form page response to the auth message history to aid cookie session tracking
  AuthenticationHelper.addAuthMessageToHistory(msg);

  // Extract acsrf tokens from the response
  const acsrfTokens = extCsrf.getTokensFromResponse(msg);

  // Accumulate the tokens and credentials for the form post on an Object.
  let formObj = {};
  log(`csrf tokens count: ${acsrfTokens.size()}`);
  acsrfTokens.forEach((token) => {
    formObj[token.name] = token.value;
    log(`adding csrf token ${token.name} = ${token.value}`);
  });
  addCredentials(formObj, credentials);

  // Build the request body from the form Object
  let requestBody = "";
  const formType = paramsValues.get("formType");
  log(`formObj: ${JSON.stringify(formObj)}`)
  // Encode as  or form
  if (formType != null && formType === "JSON") {
    requestBody = JSON.stringify(formObj);
  } else {
    requestBody = buildForm(formObj);
  }

  log(`POST: ${requestBody}`);

  url = paramUrl(paramsValues, "loginPage");
  requestUri = new URI(url, false);
  requestHeader = new HttpRequestHeader(HttpRequestHeader.POST, requestUri, HttpHeader.HTTP11)
  msg = helper.prepareMessage();
  msg.setRequestHeader(requestHeader);
  msg.setRequestBody(requestBody);

  // Set the contentLength header from the length of the encoded request body
  requestHeader.contentLength = msg.requestBody.length();

  // Make the HTTP request
  helper.sendAndReceive(msg);

  log(`req/resp2: ${logMsg(msg)}`)

  /**
   *   Return response message from the authentication form post.
   *   The response header and body will be evaluated against the app.authentication.testPath
   *   as well as the app.loggedIn/OutIndicators. If the response is determined to be
   *   valid the response will also be passed to the session mgmt method
   *   for evaluation.
   */
  return msg;
}

/**
 * The list of required parameters, the script will fail if these are not present.
 * They are available on the paramsValues map in the authenticate() function
 * @returns {string[]}
 */
function getRequiredParamsNames() {
  return ["loginPagePath", "loginPage", "remember"];
}

/**
 * The list of credential parameters.
 * They are available on the credentials map in the authenticate() function
 * These parameters MUSt match the names in app.authentication.script.credentials.
 * @returns {string[]}
 */
function getCredentialsParamsNames() {
  return ["username", "password"];
}

/**
 * The list of optional parameters/
 * They are available on the paramsValues map in the authenticate() function.
 * A parameter MUST be included here if passed in the app.authentication.script.parameters map
 * or it will not be available on the paramsValues map.
 * @returns {string[]}
 */
function getOptionalParamsNames() {
  return ["logging", "formType"];
}

