/**
 * Access Policy Utils Helper function
 * 
 * Requirement:
 * importMappingRule("standardUtils", "loggerUtils"); 
 */

importClass(Packages.com.ibm.security.access.policy.decision.Decision);
importClass(Packages.com.ibm.security.access.policy.decision.HtmlPageDenyDecisionHandler);
importClass(Packages.com.ibm.security.access.policy.decision.RedirectDenyDecisionHandler);
importClass(Packages.com.ibm.security.access.policy.decision.HtmlPageChallengeDecisionHandler);
importClass(Packages.com.ibm.security.access.policy.decision.RedirectChallengeDecisionHandler);

var accessPolicy = new function () {
    /**
     * Returns the headers of the request as a JSON object.
     * @returns {Object} The header names and values in a JSON object.
     */
    this.getHeaders = function () {
        var request = context.getRequest();
        if (!request) {
            logger.warning("accessPolicy.getHeaders: Request object is null");
            return {};
        }
        
        var returnHeaders = {};
        var headerNames = request.getHeaderNames();
        
        // Loop through all header names and add them to the returnHeaders object
        while (headerNames.hasNext()) {
            var headerName = "" + headerNames.next();
            var headerValue = "" + request.getHeader(headerName);
            returnHeaders[headerName] = headerValue;
        }
        
        return returnHeaders;
    },
    /**
     * Returns the parameters of the request as a JSON object.
     * @returns {Object} The parameter names and values in a JSON object.
     */
    this.getParameters = function () {
        var request = context.getRequest();
        if (!request) {
            logger.warning("accessPolicy.getParameters: Request object is null");
            return {};
        }

        var returnParameters = {};
        var parameterNames = request.getParameterNames();
        
        // Loop through all parameter names and add them to the returnParameters object
        while (parameterNames.hasNext()) {
            var parameterName = "" + parameterNames.next();
            var parameterValue = "" + request.getParameter(parameterName);
            returnParameters[parameterName] = parameterValue;
        }
        
        return returnParameters;
    },
    /**
     * Returns the user attributes in a JSON object.
     * @returns {Object} The user attributes and values in a JSON object.
     */
    this.getUserContext = function () {
        var userContext = context.getUser();
        if (!userContext) {
            logger.warning("accessPolicy.getUserContext: User context is null");
            return {
                username: "",
                authenticated: false,
                attributes: {}
            };
        }

        var returnUser = {};
        returnUser.username = userContext.getUsername() ? "" + userContext.getUsername() : "";
        returnUser.attributes = {};

        var returnUser = {
            username: userContext.getUsername() ? "" + userContext.getUsername() : "",
            authenticated: true,
            attributes: {}
        };
        
        var attributeNames = userContext.getAttributes();
        while (attributeNames.hasNext()) {
            var attribute = attributeNames.next();
            var attributeName = "" + attribute.getName();
            var attributeValue = "" + attribute.getValue();
            returnUser.attributes[attributeName] = attributeValue;
        }

        return returnUser;
    },
    /**
     * Returns the complete request context in a JSON object.
     * @returns {Object} Complete request context in a JSON object.
     */
    this.getRequestContext = function () {
        return {
            headers: this.getHeaders(),
            parameters: this.getParameters(),
            user: this.getUserContext(),
            client: "" + context.getProtocolContext().getClientId(),
            request_params: JSON.parse(context.getProtocolContext().getAuthenticationRequest().toString())
        };
    };
}