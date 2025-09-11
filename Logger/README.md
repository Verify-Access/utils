# Simple Logger Function for Verify Access
A simple, easily searchable, standard logging object that can be used repeatably throughout mapping rules in Verify Access (or formally known as IBM Security Access Manager (ISAM)).

This logger function allows for simple integration into tools such as Logstash/Kibana.

## Importing Logger Utils

```javascript
importMappingRule("loggerUtils_lightweight"); 
```

> `loggerUtils.js` requires `standardUtils.js`. You MUST import this mapping rule or it will result in runtime exceptions.

```javascript
importMappingRule("standardUtils", "loggerUtils"); 
```

## Using the Logger Function

```javascript
// Importing `loggerUtils` will intiate the logger function.
// Start by intiating one of the 'doing' functions.
logger.doingInfoMap();
logger.user = getInfoMapValue("username", INFOMAP_ATTRIBUTE, "unauthenticated");
logger.type = "API";
logger.event = "GRANTS";

// Add your code.
grant = true;
if (grant) {
    // A 'grant' exists.
    logger.success("We found a grant.");
} else {
    logger.error("We couldn't find a grant.");
}
```

Another example for an OAuth mapping rule may look like this.

```javascript
requestType = getAttributeValue("request_type", "urn:ibm:names:ITFIM:oauth:request", CONTEXT, "null")
grantType = getAttributeValue("grant_type", "urn:ibm:names:ITFIM:oauth:request", CONTEXT, "null")
logger.doingOidcOp();

logger.verbose("Begin OAuthPreTokenGeneration. request_type: " + requestType + ". grant_type: " + grantType + ". STSUU: " + stsuu.toString());

logger.verbose("End OAuthPreTokenGeneration. request_type: " + requestType + ". grant_type: " + grantType + ". STSUU: " + stsuu.toString());
```

## Extracting Log Statements
To extract logger statements, simply run this `grep` over the `trace.log` file. This will pull out all matching lines into a new file called `result.log`.

```bash
grep -o '##Verify_Access_Logger_ver=1.0.0##.*' trace.log > result.log
```