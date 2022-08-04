/*
 *  Script which tries to access users that belong to another tenant of the logged in user
 */
var RISK = 2 // 0: info, 1: low, 2: medium, 3: high
var CONFIDENCE = 3 // 0: falsePositive, 1: low, 2: medium, 3: high, 4: confirmed
var TITLE = "Tenancy Check failed"
var DESCRIPTION = "User was able to access users not in their company"
var SOLUTION = "Enforce tenancy"
var REFERENCE = "https://personal.rhul.ac.uk/vsai/149/Multi-tenancy%20doc%20300614.pdf"
var OTHER = "see: https://www.cloudreach.com/en/blog/multi-tenant-security-in-the-cloud-what-you-need-to-know/"
var PLUGIN_ID = "" //Custom Plugin ID

function log(msg) {
    print("[" + this["zap.script.name"] + "] " + msg);
}

function alert(as, msg, evidence) {
    as.newAlert()
        .setPluginId(PLUGIN_ID)
        .setRisk(RISK)
        .setConfidence(CONFIDENCE)
        .setName(TITLE)
        .setDescription(DESCRIPTION)
        .setEvidence(evidence)
        .setOtherInfo(OTHER)
        .setSolution(SOLUTION)
        .setReference(REFERENCE)
        .setMessage(msg)
        .raise();
}

function scanNode(as, msg) {

    var uri = msg.getRequestHeader().getURI();


    log("scanning " + uri);

    // Copy requests before reusing them
    msg = msg.cloneRequest();


    var request_header = msg.getRequestHeader();
    uri = request_header.getURI();

    //Path to request users
    uri.setPath(uri.getPath().toString() +  "/user");

    request_header.setHeader("Content-Type", "application/json");

    // sendAndReceive(msg, followRedirect, handleAntiCSRFtoken)
    as.sendAndReceive(msg, false, false);

    var response_header = msg.getResponseHeader();
    var response_body = msg.getResponseBody();

    //Check for users outside of logged in user's tenancy
    var evidence_idx = response_body.toString()
        .indexOf("user4");

    log(msg);

    // Test the response here, and make other requests as required
    if (response_header.getStatusCode() == 200 && evidence_idx >= 0) {
        alert(as, msg, response_body.toString().substring(evidence_idx));
    }

}

function scan(as, msg, param, value) {
    return;
}