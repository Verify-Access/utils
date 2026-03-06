/**
 * Standard Utils Helper function
 */

// Standard Imports.
importPackage(Packages.com.tivoli.am.fim.trustserver.sts);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.oauth20);
importPackage(Packages.com.tivoli.am.fim.trustserver.sts.uuser);
importPackage(Packages.com.ibm.security.access.user);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.IDMappingExtUtils);
importClass(Packages.com.tivoli.am.fim.trustserver.sts.utilities.OAuthMappingExtUtils);
importClass(Packages.com.ibm.security.access.httpclient.HttpClient);
importClass(Packages.com.ibm.security.access.httpclient.HttpResponse);
importClass(Packages.com.ibm.security.access.httpclient.Headers);
importClass(Packages.com.ibm.security.access.httpclient.Parameters);
importClass(Packages.java.util.ArrayList);
importClass(Packages.java.util.HashMap);
importClass(Packages.com.ibm.security.access.server_connections.ServerConnectionFactory);
importClass(Packages.com.tivoli.am.fim.fedmgr2.trust.util.LocalSTSClient);
importClass(Packages.java.lang.System);

// const CONTEXT = 'CONTEXT';
const ATTRIBUTE = 'ATTRIBUTE';
const REQUEST = 'REQUEST';

/**
 * Retrieves the named attribute from the *default* STSUU and converts to a JS Array full of JS Strings.
 * @param  {String} name        Name of the attribute in the STSUU
 * @param  {String} type        Type of the attribute in the STSUU
 * @param  {String} container   Will be one of "context" | "attribute" | "request"
 * @return {Array}              Array of Strings (or empty in the Null case)
 */
function getAttributeValues(name, type, container) {
    if (container === "CONTEXT") {
        values = stsuu.getContextAttributes().getAttributeValuesByNameAndType(name, type);
    } else if (container === "ATTRIBUTE") {
        values = stsuu.getAttributeContainer().getAttributeValuesByNameAndType(name, type);
    } else if (container === "REQUEST") {
        values = stsuu.getRequestSecurityToken().getAttributeValuesByNameAndType(name, type);
    }

    if (values != null) {
        values = values.map(function (value) {
            // force the JS string conversion
            if (value != null) {
                value = '' + value;
            }
            return value;
        });
    } else {
        values = [];
    }
    return values;
}

/**
 * Gets the attribute from the STSUU (as a String) or returns the default Value.
 * @param  {String} name            Name of the attribute in the STSUU
 * @param  {String} type            Type of the attribute in the STSUU
 * @param  {String} container       Will be one of "context" | "attribute" | "request"
 * @param  {*}      defaultValue    Default Value (any type) to return
 * @return {*}                      String if there is a value, default if not.
 */
function getAttributeValue(name, type, container, defaultValue) {
    var values = getAttributeValues(name, type, container);
    if (values == null || values.length == 0) {
        return defaultValue;
    }
    return values[0];
}

const RST_HEADER = "Header"
const RST_COOKIES = "Cookie"
const RST_ATTRIBUTES = "Attribute"

function getRstClaims(attrType, attrName, defaultValue, wantArray) {
    var claims = stsuu.getRequestSecurityToken().getAttributeByName("Claims").getNodeValues();

    for (var i = 0; i < claims.length; i++) {
        var dialect = claims[i].getAttribute("Dialect");

        if ("urn:ibm:names:ITFIM:httprequest".equalsIgnoreCase(dialect)) {
            var attrs = claims[i].getElementsByTagName(attrType);

            for (var j = 0; j < attrs.getLength(); j++) {
                var item = attrs.item(j);
                var name = item.getAttribute("Name");
                var values = item.getElementsByTagName("Value");
                if (name == attrName) {
                    if (values.getLength() == 0) {
                        return defaultValue
                    } else if (!wantArray) {
                        return "" + values.item(0).getTextContent();
                    } else {
                        var returnArray = []
                        for (var k = 0; k < values.getLength(); k++) {
                            returnArray.push("" + values.item(k).getTextContent())
                        }
                        return returnArray;
                    }
                }
            }
        }
    }
}

/**
 * Gets an array of attributes from the STSUU (All that match the same type).
 * @param  {String} type            Type of the attribute in the STSUU
 * @param  {String} container       Will be one of "context" | "attribute" | "request"
 * @return {object}                 Javascript object with JS strings for each key and value.
 */
function getAllAttributes(type, container) {
    if (container === CONTEXT) {
        attrs = stsuu.getContextAttributes().getAttributesByType(type);
    } else if (container === ATTRIBUTE) {
        attrs = stsuu.getAttributeContainer().getAttributesByType(type);
    } else if (container === REQUEST) {
        attrs = stsuu.getRequestSecurityToken().getAttributesByType(type);
    }

    // We have an array of Attributes - which might then individually have an array of attribute values
    if (attrs != null) {
        attrs = attrs.map(function (attr) {
            var ret = {}
            if (attr != null) {
                values = attr.getValues()
                values = values.map(function (value) {
                    if (value != null) {
                        value = value + ""
                    }
                    return value
                })
                // return a string for one, an array for multiple.
                if (values.length == 1) {
                    ret["" + attr.getName()] = values[0]
                } else {
                    ret["" + attr.getName()] = values
                }

            }
            return ret;
        });
    } else {
        attrs = [];
    }
    var allAttrs = {}
    for (k in attrs) {
        Object.assign(allAttrs, attrs[k])
    }

    return allAttrs;
}

/**
 * Gets the Names of all the attributes that match a specific type in the STSUU. Really useful for scopes.
 * @param  {String} type            Type of the attribute in the STSUU
 * @param  {String} container       Will be one of "context" | "attribute" | "request"
 * @return {object}                 Javascript object with JS strings for each key and value.
 */
function getAllAttributeNames(type, container) {
    if (container === CONTEXT) {
        attrs = stsuu.getContextAttributes().getAttributesByType(type);
    } else if (container === ATTRIBUTE) {
        attrs = stsuu.getAttributeContainer().getAttributesByType(type);
    } else if (container === REQUEST) {
        attrs = stsuu.getRequestSecurityToken().getAttributesByType(type);
    }

    // We have an array of Attributes - which might then individually have an array of attribute values
    if (attrs != null) {
        attrs = attrs.map(function (attr) {
            return "" + attr.getName()
        });
    } else {
        attrs = [];
    }

    return attrs;
}

const INFOMAP_PARAM = "urn:ibm:security:asf:request:parameter";
const INFOMAP_ATTRIBUTE = "urn:ibm:security:asf:request:token:attribute";
const INFOMAP_HEADER = "urn:ibm:security:asf:request:header";

function getInfoMapValue(name, type, defaultValue) {
    let tempVal = context.get(Scope.REQUEST, type, name);
    if (tempVal != null && tempVal.length() > 0) {
        return "" + tempVal;
    } else {
        return defaultValue;
    }
}

/**
 * Redirects browser to custom URL from Infomap. Will only work if template script is 
 * @param {string} targetUrl Full redirect URL
 */
function setInfoMapValue(key, value) {
    context.set(Scope.SESSION, "urn:ibm:security:asf:response:token:attributes", key, value);
}


/**
 * Converts a JS to a Java Array.  Used in OTP and some OIDC cases.  Is originally supplied in OTPGetMethods.js.
 * @param  {Array} jsArray          JS Array to convert
 * @return {*}                      Java Array.
 */
function jsToJavaArray(jsArray) {
    var javaArray = java.lang.reflect.Array.newInstance(java.lang.String, jsArray.length);
    for (var i = 0; i < jsArray.length; i++) {
        javaArray[i] = jsArray[i];
    }
    return javaArray;
}

/**
 * Converts a Java to a JS Array. 
 * @param  {Array} arr              Java Array to convert
 * @return {*}                      JS Array.
 */
function javaToJsArray(arr) {
    if (arr != null) {
        values = arr.map(function (value) {
            // force the JS string conversion
            if (value != null) {
                value = '' + value;
            }
            return value;
        });
    } else {
        values = [];
    }
    return values;
}

/**
 * Base64 Encode/Decode
 */
var base64 = new function () {
    this.decode = function (string) {
        return "" + new java.lang.String(java.util.Base64.getMimeDecoder().decode(string));
    }
    this.encode = function (string) {
        var sfar = java.lang.reflect.Array.newInstance(java.lang.String, 1);
        sfar[0] = string;
        return "" + java.util.Base64.getEncoder().encodeToString(sfar[0].getBytes());
    }
}


/**
 * Input validation.
 */
var inputValidate = new function () {
    /**
     * Validate URL matches an expected host.
     * @param {string} fullUrl Full URL to check.
     * @param {string} hostToLookFor Either the full or partial host name, e.g. `login.my.gov.au` | `.gov.au`. Partial host names SHOULD start with a `.` (full stop).
     * @returns {boolean} Returns `true` if URL contains expected host, else returns `false`.
     */
    this.host = function (fullUrl, hostToLookFor) {
        // Input validation
        if (!fullUrl || typeof fullUrl !== 'string' || !hostToLookFor || typeof hostToLookFor !== 'string' || hostToLookFor === "." || hostToLookFor === "") {
            logger.warning("inputValidate.host: Invalid input parameters");
            return false;
        }
        
        // URL parsing regex - RFC 3986 compliant
        var regex = /^(([^:\/?#]+):)?(\/\/([^\/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?/;
        var found = fullUrl.match(regex);
        
        // Validate regex matched and host exists
        if (!found || !found[4]) {
            logger.warning("inputValidate.host: Invalid URL format: " + fullUrl);
            return false;
        }
        
        // Extract host and remove port if present
        var host = found[4].split(':')[0].toLowerCase();
        var hostToMatch = hostToLookFor.toLowerCase();
        
        // Check for malicious characters
        if (host.includes('@') || host.includes('\\') || host.includes(' ')) {
            logger.warning("inputValidate.host: Suspicious characters in host: " + host);
            return false;
        }
        
        var isValid = false;
        
        if (hostToMatch.startsWith(".")) {
            // Partial host name
            isValid = host.endsWith(hostToMatch) || host === hostToMatch.substring(1);
        } else {
            // Full host name
            isValid = (host === hostToMatch);
        }
        
        return isValid;
    };

    /**
     * Validate URL is well-formed and uses allowed protocols
     * @param {string} url URL to validate
     * @param {Array<string>} allowedProtocols Allowed protocols (default: ['http', 'https'])
     * @returns {boolean} True if valid URL
     */
    this.url = function (url, allowedProtocols) {
        // Input validation.
        if (!url || typeof url !== 'string') {
            return false;
        }
        
        allowedProtocols = allowedProtocols || ['http', 'https'];
        
        try {
            var regex = /^(([^:\/?#]+):)?(\/\/([^\/?#]*))?([^?#]*)(\?([^#]*))?(#(.*))?/;
            var match = url.match(regex);
            
            if (!match || !match[2] || !match[4]) {
                return false;
            }
            
            var protocol = match[2].toLowerCase();
            return allowedProtocols.indexOf(protocol) !== -1;
        } catch (e) {
            return false;
        }
    };

    /**
     * Validate an email is an email per RFC 5321.
     * @param {string} email Email to validate.
     * @returns {boolean} Returns `true` if string is an email, else returns `false`.
     */
    this.email = function (email) {
        // Input validation.
        if (!email || typeof email !== 'string') {
            return false;
        }
        
        // Total address length check.
        if (email.length > 254) {
            return false;
        }
        
        // Comprehensive email regex
        var regex = /^[a-zA-Z0-9.!#$%&'*+\/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+$/;
        
        // Check for consecutive dots.
        if (email.includes('..')) {
            return false;
        }
        
        var parts = email.split('@');
        // Add check for leading/trailing dots in local part.
        if (parts[0].startsWith('.') || parts[0].endsWith('.')) {
            return false;
        }
        // Multiple @ symbols.
        if (parts.length !== 2) {
            return false;
        }
        // Check local part length.
        if (parts[0].length > 64) {
            return false;
        }
        
        return regex.test(email);
    };

    /**
     * Determine the type of the value.
     * @param {*} input Value to determine type of.
     * @returns {string} Returns one of: "null", "undefined", "array", "object", "boolean", "integer", "float", "string"
     */
    this.determineType = function (input) {
        // Handle null and undefined explicitly.
        if (input === null) {
            return "null";
        }
        if (input === undefined) {
            return "undefined";
        }
        
        // Check actual JavaScript type first.
        var jsType = typeof input;
        
        if (jsType === "object") {
            // Distinguish between array and object.
            return Array.isArray(input) ? "array" : "object";
        }
        
        if (jsType === "boolean") {
            return "boolean";
        }
        
        if (jsType === "number") {
            return Number.isInteger(input) ? "integer" : "float";
        }
        
        // For strings, try to infer the intended type.
        if (jsType === "string") {
            // Empty string
            if (input === "") {
                return "string";
            }
            
            // Check for JSON object/array.
            if ((input.startsWith('{') && input.endsWith('}')) || 
                (input.startsWith('[') && input.endsWith(']'))) {
                try {
                    JSON.parse(input);
                    return "object";
                } catch (e) {
                    return "string";
                }
            }
            
            // Check for boolean strings.
            if (input === "true" || input === "false") {
                return "boolean";
            }
            
            // Check for numeric strings.
            var num = Number(input);
            if (!isNaN(num) && input.trim() !== "") {
                return Number.isInteger(num) ? "integer" : "float";
            }
            
            return "string";
        }
        
        // Fallback for any other types.
        return jsType;
    };

    /**
     * Validate UUID format (v4)
     * @param {string} uuid UUID string to validate
     * @returns {boolean} True if valid UUID
     */
    this.uuid = function (uuid) {
        if (!uuid || typeof uuid !== 'string') {
            return false;
        }
        var regex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        return regex.test(uuid);
    };

    /**
     * Validate JWT format (basic structure check)
     * @param {string} token JWT token to validate
     * @returns {boolean} True if valid JWT structure
     */
    this.jwt = function (token) {
        if (!token || typeof token !== 'string') {
            return false;
        }
        var regex = /^[A-Za-z0-9_-]+=*\.[A-Za-z0-9_-]+=*\.[A-Za-z0-9_-]*=*$/;
        return regex.test(token);
    };
}