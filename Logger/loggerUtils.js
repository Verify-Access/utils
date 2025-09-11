const LOG_SEVERE = java.util.logging.Level.SEVERE
const LOG_WARNING = java.util.logging.Level.WARNING
const LOG_INFO = java.util.logging.Level.INFO
const LOG_FINE = java.util.logging.Level.FINE
const LOG_FINER = java.util.logging.Level.FINER
const LOG_FINEST = java.util.logging.Level.FINEST

const SUCCESS = "SUCCESS"
const FAILED = "FAILED"
const ORPHAN = "ORPHAN"
const DENIED = "DENIED"
const EXPIRED = "EXPIRED"
const ERROR = "ERROR"
const WARN = "WARN"
const LOG = "LOG"
const CONTEXT = "CONTEXT"
const DEBUG = "DEBUG"
const VERBOSE = "VERBOSE"

const LOG_LEVELS = {
    SUCCESS: LOG_SEVERE, // Terminal action. Should only be logged once per mapping rule.
    FAILED: LOG_SEVERE, // Terminal action. Should likely only be logged in an error scenario.
    ORPHAN: LOG_SEVERE, // Terminal action. For when login failed due to not finding the ID.
    DENIED: LOG_SEVERE, // Terminal action. User didn't pass authorization/etc.
    EXPIRED: LOG_SEVERE, // Terminal action. User/Token expired.
    ERROR: LOG_SEVERE,
    WARN: LOG_WARNING,
    LOG: LOG_INFO,
    CONTEXT: LOG_FINE,
    DEBUG: LOG_FINER,
    VERBOSE: LOG_FINEST
}

// Control which logging events are written to either the `trace.log` or `message.log` files. Default: All events are written to `trace.log`.
const TRACE_LOG_LEVELS = [LOG_SEVERE, LOG_WARNING, LOG_INFO, LOG_FINE, LOG_FINER, LOG_FINEST];
const MESSAGE_LOG_LEVELS = [];

const LOGGER_NAME = "Verify_Access_Logger"
const LOGGER_VERSION = "1.2.0"

function getDetailedTimestamp() {
    // Format aligned to what Logstash expects.
    var ts = new Date();
    return ts.getFullYear() + "-" + ("0" + (ts.getMonth() + 1)).slice(-2) + "-" + ("0" + ts.getDate()).slice(-2) + "T" + ("00" + ts.getHours()).slice(-2) + ":" + ("00" + ts.getMinutes()).slice(-2) + ":" + ("00" + ts.getSeconds()).slice(-2) + "." + ("000" + ts.getMilliseconds()).slice(-3);
}

const LOG_OBJECT = {
    correlation: "" + java.util.UUID.randomUUID(), // Transaction ID.
    program: "", // Setup when the object is initialised.
    protocol: "",
    type: "",
    event: "",
    user: "",
    partner: "",
    partnerId: "",
    sessionId: "",
    resource: "",
    state: "",
    user_agent: "",
    webseal: "",
    runtime: "", // Add hostname details into field during deployment.
    srcIp: "",
    init: new Date(), // Timestamp logger was initialized.
    lastTime: new Date(), // Timestamp of last time a logger.log() was written.
    timers: {},
    timerResults: {},

    /**
     * Logger tracing function to print messages to the `trace.log` file.
     * @param {keyof LOG_LEVELS} eventId One of the defined Logger event IDs
     * @param {String} message 
     */
    log: function (eventId, message) {
        message = message || "";
        currentTime = new Date();
        output = {
            "_timestamp": "" + getDetailedTimestamp(),
            "delta": currentTime - this.lastTime,
            "total": currentTime - this.init,
            "inst": "" + this.program,
            "protocol": "" + this.protocol,
            "type": "" + this.type,
            "event": "" + this.event,
            "msg": "" + eventId,
            "user": "" + this.user,
            "partner": "" + this.partner,
            "partnerid": "" + this.partnerId,
            "session": "" + this.sessionId,
            "resource": "" + this.resource,
            "ip": "" + this.srcIp,
            "webseal": "" + this.webseal,
            "state": "" + this.state,
            "device_agent": "" + this.user_agent,
            "runtime": "" + this.runtime,
            "correlation": this.correlation,
            "details": "" + message
        }
        for (result in this.timerResults) {
            output["timer_" + result] = this.timerResults[result]
        }

        // Write event to `trace.log` if logging level is in allowed array.
        if (TRACE_LOG_LEVELS.includes(LOG_LEVELS[eventId])) {
            IDMappingExtUtils.traceString("##" + LOGGER_NAME + "_ver=" + LOGGER_VERSION + "##" + JSON.stringify(output), LOG_LEVELS[eventId]);
        }
        // Write event to `message.log` if logging level is in allowed array.
        if (MESSAGE_LOG_LEVELS.includes(LOG_LEVELS[eventId])) {
            System.out.println("##" + LOGGER_NAME + "_ver=" + LOGGER_VERSION + "##" + JSON.stringify(output));
        }
        this.lastTime = currentTime;
    },

    success: function (text) {
        this.log(SUCCESS, text);
    },
    failed: function (text) {
        this.log(FAILED, text);
    },
    orphan: function (text) {
        this.log(ORPHAN, text);
    },
    denied: function (text) {
        this.log(DENIED, text);
    },
    expired: function (text) {
        this.log(EXPIRED, text);
    },
    error: function (text) {
        this.log(ERROR, text);
    },
    warning: function (text) {
        this.log(WARN, text);
    },
    info: function (text) {
        this.log(LOG, text);
    },
    context: function (text) {
        this.log(CONTEXT, text);
    },
    debug: function (text) {
        this.log(DEBUG, text);
    },
    verbose: function (text) {
        this.log(VERBOSE, text);
    },

    /**
     * Initiates timer function.
     * @param {String} name Name of timer
     */
    startTimer: function (name) {
        this.timers[name] = new Date();
    },

    /**
     * Records the result of `startTimer()` in milliseconds.
     * @param {string} name Name of the timer
     */
    stopTimer: function (name) {
        if (this.timers.hasOwnProperty(name)) {
            var stopTimerResult = new Date() - this.timers[name];
            this.timerResults[name] = stopTimerResult;
        }
    },

    doingOidcOp: function () {
        this.protocol = "OIDC";
        this.type = "IDP";
        this.webseal = getRstClaims(RST_HEADER, "iv_server_name", "", false);
        this.srcIp = getRstClaims(RST_HEADER, "x-forwarded-for", "", false);
        this.user_agent = getRstClaims(RST_HEADER, "user-agent", "", false);
    },

    doingOidcRp: function () {
        this.protocol = "OIDC";
        this.type = "RP";
        this.event = "LOGIN";
        this.partnerId = getAttributeValue("sub", "urn:ibm:names:ITFIM:5.1:accessmanager", ATTRIBUTE, "");
        this.webseal = getAttributeValue("iv_server_name", "urn:ibm:SAM:oidc:rp:http:header", CONTEXT, "");
        this.srcIp = getAttributeValue("x-forwarded-for", "urn:ibm:SAM:oidc:rp:http:header", CONTEXT, getAttributeValue("iv-remote-address", "urn:ibm:SAM:oidc:rp:http:header", CONTEXT, ""));
        this.user_agent = getAttributeValue("user-agent", "urn:ibm:SAM:oidc:rp:http:header", CONTEXT, "");
        this.state = getAttributeValue("state", "urn:ibm:SAM:oidc:rp:authorize:rsp:param", CONTEXT, "");
    },

    doingOidcAdvanced: function () {
        this.protocol = "OIDC";
        this.type = "RP";
        this.partnerId = getAttributeValue('client_id', 'urn:ibm:SAM:oidc:rp:meta', CONTEXT, getAttributeValue('client_id', 'urn:ibm:SAM:oidc:rp:authorize:req:param', CONTEXT, ""));
        this.event = getAttributeValue('operation', 'urn:ibm:SAM:oidc:rp:operation', CONTEXT, '');
        this.webseal = getAttributeValue("iv_server_name", "urn:ibm:SAM:oidc:rp:http:header", CONTEXT, "");
        this.srcIp = getAttributeValue("x-forwarded-for", "urn:ibm:SAM:oidc:rp:http:header", CONTEXT, getAttributeValue("iv-remote-address", "urn:ibm:SAM:oidc:rp:http:header", CONTEXT, ""));
        this.user_agent = getAttributeValue("user-agent", "urn:ibm:SAM:oidc:rp:http:header", CONTEXT, "");
        this.state = getAttributeValue("state", "urn:ibm:SAM:oidc:rp:authorize:rsp:param", CONTEXT, getAttributeValue("state", "urn:ibm:SAM:oidc:rp:authorize:req:param", CONTEXT, ""));
    },

    doingAuthorize: function () {
        this.doingOidcOp();
        this.event = "AUTHORIZE";
        this.user = "" + stsuu.getPrincipalName()
        this.partner = "" + oauth_client.getClientId();
    },

    doingUserInfo: function () {
        this.doingOidcOp();
        this.event = "USERINFO";
        this.user = getAttributeValue("oidc_username", "urn:ibm:names:ITFIM:5.1:accessmanager", ATTRIBUTE, "unknown");
        this.partner = getAttributeValue("client_id", "urn:ibm:names:ITFIM:oauth:response:metadata", CONTEXT, "");
    },

    doingToken: function () {
        this.doingOidcOp();
        this.event = "TOKEN";
        this.user = getAttributeValue("oidc_username", "urn:ibm:names:ITFIM:5.1:accessmanager", ATTRIBUTE, "unknown");
        this.partner = "" + oauth_client.getClientId();
    },

    doingOAuthSession: function () {
        this.doingOidcOp();
        this.event = "LOGIN";
        this.protocol = "OAUTH";
        this.user = getAttributeValue("oidc_username", "urn:ibm:names:ITFIM:5.1:accessmanager", ATTRIBUTE, "unknown");
        this.partner = "" + oauth_client.getClientId();
    },

    doingInfoMap: function () {
        this.protocol = "INFO";
        this.webseal = getInfoMapValue("iv_server_name", INFOMAP_HEADER, "");
        this.srcIp = getInfoMapValue("x-forwarded-for", INFOMAP_HEADER, getInfoMapValue("iv-remote-address", INFOMAP_HEADER, ""));
        this.user_agent = getInfoMapValue("user-agent", INFOMAP_HEADER, "");
        this.user = getInfoMapValue("username", INFOMAP_ATTRIBUTE, "");
    },

    doingSaml: function () {
        this.protocol = "SAML";
        this.type = "IDP";
        this.event = "TOKEN";
        this.webseal = getRstClaims(RST_HEADER, "iv_server_name", "", false);
        this.srcIp = getRstClaims(RST_HEADER, "x-forwarded-for", "", false);
        this.user_agent = getRstClaims(RST_HEADER, "user-agent", "", false);
    },

    doingOauthResource: function () {
        this.webseal = getAttributeValue("iv_server_name", "urn:ibm:names:ITFIM:oauth:header:param", CONTEXT, "");
        this.srcIp = getAttributeValue("x-forwarded-for", "urn:ibm:names:ITFIM:oauth:header:param", CONTEXT, getAttributeValue("iv-remote-address", "urn:ibm:names:ITFIM:oauth:header:param", CONTEXT, ""));
        this.user_agent = getAttributeValue("user-agent", "urn:ibm:names:ITFIM:oauth:header:param", CONTEXT, "");
        this.event = "RESOURCE";
        this.protocol = "OAUTH";
        this.type = "RP";
        this.resource = getAttributeValue("path", "urn:ibm:names:ITFIM:oauth:request", CONTEXT, "");
        this.user = getAttributeValue("oidc_username", "urn:ibm:names:ITFIM:5.1:accessmanager", ATTRIBUTE, "unknown");
        this.partner = getAttributeValue("oauth_token_client_id", "urn:ibm:names:ITFIM:oauth:response:attribute", CONTEXT, "");
    },

    doingOTP: function () {
        this.webseal = getAttributeValue("iv_server_name", "otp.useragent.httpheader.type", CONTEXT, "");
        this.srcIp = getAttributeValue("x-forwarded-for", "otp.useragent.httpheader.type", CONTEXT, getAttributeValue("iv-remote-address", "otp.useragent.httpheader.type", CONTEXT, ""));
        this.user_agent = getAttributeValue("user-agent", "otp.useragent.httpheader.type", CONTEXT, "");
        this.protocol = "OTP";
        this.type = "SESSION";
        this.user = "" + stsuu.getPrincipalName()
    },

    doingAccessPolicy: function () {
        request = context.getRequest();
        user = context.getUser();

        this.protocol = "ACCESS_POLICY";
        this.type = "DECISION";
        this.event = "LOGIN";
        this.user = user ? "" + user.username : "unauthenticated";
        this.partner = "" + context.getProtocolContext().getClientId();
        this.webseal = request.getHeader("iv_server_name");
        this.srcIp = request.getHeader("x-forwarded-for") ? request.getHeader("x-forwarded-for") : request.getHeader("iv-remote-address");
        this.user_agent = request.getHeader("User-Agent");
    }
}

// Initializes logging object.
logger = Object.create(LOG_OBJECT);
