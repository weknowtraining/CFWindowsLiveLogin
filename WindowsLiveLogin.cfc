<cfcomponent displayname="Windows Live Login" 
  description="Windows Live ID Web Authentication SDK">

  <cfinclude template="udf_binary.cfm">

  <!--- debugging --->
  <cffunction name="setDebug" access="public" output="no" returnType="void">
    <cfargument name="log_enabled" required="yes" type="boolean">
    <cfset Variables.log_enabled = log_enabled>
  </cffunction>

  <cffunction name="debug" access="private" output="no" returnType="void">
    <cfargument name="error" required="yes" type="string">
    <cfargument name="error_type" required="no" type="string" default="Warning">
    <cfif Variables.log_enabled>
      <cflog text="#error#" file="WindowsLiveLogin" type="#error_type#">
    </cfif>
  </cffunction>

  <cffunction name="fatal" access="private" output="no" returnType="void">
    <cfargument name="error" required="yes" type="string">
    <cfscript>debug(error, "Fatal");</cfscript>
    <cfthrow type="WLLError" message="#error#">
  </cffunction>
  
  <!--- constructor/accessors --->
  <cffunction name="init" access="public" output="no" returnType="WindowsLiveLogin"
    description="Initialize the WindowsLiveLogin module with the application ID,
                 secret key, and security algorithm.">
    <cfargument name="appid" required="no" type="string" default="">
    <cfargument name="secret" required="no" type="string" default="">
    <cfargument name="security_algorithm" required="no" type="string" default="">
    <!--- private variables --->
    <cfscript>
    Variables.log_enabled = false;
    Variables.appid = "";
    Variables.cryptKey = "";
    Variables.signKey = "";
    Variables.securityAlgorithm = "";
    
    if(Len(appid)) { setAppId(appid); }
    if(Len(secret)) { setSecret(secret); }
    if(Len(security_algorithm)) { setSecurityAlgorithm(security_algorithm); }
    </cfscript>
    <cfreturn This>
  </cffunction>

  <cffunction name="setAppId" access="public" output="no" returnType="void"
    description="Sets the application ID. Use this method if you did not specify
                 an application ID at initialization.">
    <cfargument name="appid" required="yes" type="string">
    <cfscript>
    if( REFind("^\w+$", appid) eq 0) {
      fatal("Error: setAppId: Application ID must be alpha-numeric: " & appid);
    }
    Variables.appid = appid;
    </cfscript>
  </cffunction>
  
  <cffunction name="getAppId" access="public" output="no" returnType="string"
    description="Returns the application ID.">
    <cfscript>
    if( Len(Variables.appid) eq 0) {
      fatal("Error: getAppId: Application ID was not set. Aborting.");
    }
    return Variables.appid;
    </cfscript>
  </cffunction>
  
  <cffunction name="setSecret" access="public" output="no" returnType="void"
    description="Sets the application ID. Use this method if you did not specify
                 an application ID at initialization.">
    <cfargument name="secret" required="yes" type="string">
    <cfscript>
    if(Len(secret) lt 16) {
      fatal("Error: setSecret: Secret must at least 16 characters.");
    }
    Variables.signKey = derive(secret, "SIGNATURE");
    Variables.cryptKey = derive(secret, "ENCRYPTION");
    </cfscript>
  </cffunction>
  
  <!--- TODO: setOldSecret, setOldSecretExpiry, getOldSecretExpiry --->
  
  <cfscript>
  function setSecurityAlgorithm(sa) {
    Variables.securityAlgorithm = sa;
  }
  
  function getSecurityAlgorithm() {
    if(Len(Variables.securityAlgorithm) gt 0) {
      return Variables.securityAlgorithm;
    }
    else {
      return "wsignin1.0";
    }
  }
  </cfscript>
  
  <!--- TODO: set/get PolicyUrl, ReturnUrl, BaseUrl, SecureUrl, ConsentBaseUrl --->
  
  <!--- TODO: processLogin --->
  <cffunction name="processLogin" access="public" output="no" returnType="struct"
    description="Processes the sign-in response from the Windows Live Login server.">
    <cfargument name="fs" required="yes" type="struct" description="Form fields">
    <cfscript>
    var token = ''; var context = '';
    var error = StructNew();
    error.valid = false;

    if( not StructKeyExists(fs, 'action') ) {
      error.error = "processLogin: No action in query.";
      debug(error.error);
      return error;
    }
    
    if( fs.action neq "login" ) {
      error.error = "processLogin: fs action ignored: " & fs.action;
      debug(error.error);
      return error;
    }
    
    if( StructKeyExists(fs, 'stoken') ) {
      token = fs.stoken;
    }
    if( StructKeyExists(fs, 'appctx') ) {
      context = URLDecode(fs.appctx);
    }
    
    return processToken(token, context);
    </cfscript>
  </cffunction>
  
  <!--- TODO: getLoginUrl, getLogoutUrl --->
  
  <cffunction name="processToken" access="public" output="no" returnType="struct"
    description="Decodes and validates the token.">
    <cfargument name="token" required="yes" type="string">
    <cfargument name="context" required="no" type="string" default="">
      
    <cfscript>
    var decodedToken = '';
    var user = StructNew(); 
    var error = StructNew(); error.valid = false;
    var appid = '';
    
    if(Len(token) eq 0) {
      error.error = 'Error: processToken: Invalid token specified.';
      debug(error.error);
      return error;
    }
    
    decodedToken = decodeAndValidateToken(token);
    //if(Len(decodedToken) eq 0) {  }
    
    decodedToken = parse(decodedToken);
    if( StructCount(decodedToken) eq 0 ) {
      error.error = 'Error: processToken: Failed to parse token after decoding: ' & token;
      debug(error.error);
      return error;      
    }
    
    if( not StructKeyExists(decodedToken, "appid") ) {
      error.error = 'Error: processToken: token does not contain application ID.';
      debug(error.error);
      return error;
    }
    
    appid = getAppId();
    if( decodedToken.appid neq appid ) {
      error.error = "Error: processToken: Application ID in token (#decodedToken.appid#) "
                    & "did not match application ID in configuration (#appid#).";
      debug(error.error);
      return error;
    }
    
    // unix time stamp
    user.timestamp = '';
    if(StructKeyExists(decodedToken, 'ts')) {
      if( IsNumeric(decodedToken.ts) and decodedToken.ts gt 0 ) {   // TODO: integers only
        user.timestamp = decodedToken.ts;
      }
      else {
        error.error = "Error: processToken: Contents of token considered invalid: "
                    & "Invalid timestamp";
        debug(error.error);
        return error;
      }
    }
    
    user.uid = '';
    if(StructKeyExists(decodedToken, 'uid')) {
      if( REFind("^\w+$", decodedToken.uid) ) {
        user.uid = decodedToken.uid;
      }
      else {
        error.error = "Error: processToken: Contents of token considered invalid: "
                    & "Invalid user id";
        debug(error.error);
        return error;
      }
    }
    
    // TODO: usePersistentCookie flag from decodedToken.flags
    user.context = context;
    user.token = token;
    user.valid = true;
    return user;
    </cfscript>  
      
  </cffunction>

  <!--- TODO: getClearCookieResponse --->
  
  <!--- TODO: getConsentUrl, getRefreshConsentTokenUrl, getManageConsentUrl, processConsent,
    processConsentToken, refreshConsentToken, refreshConsentToken2 --->
  
  <cffunction name="decodeAndValidateToken" access="public" output="no" returnType="string"
    description="Decodes and validates the token.">
    <cfargument name="token" required="yes" type="string">
    <cfargument name="cryptkey" required="no" type="string" default="">
    <cfargument name="signkey" required="no" type="string" default="">
    
    <cfscript>
    var stoken = '';
    
    if(Len(cryptkey) eq 0) { cryptkey = Variables.cryptKey; }
    if(Len(signkey) eq 0) { signkey = Variables.signKey; }
    
    // TODO: old secret
    
    stoken = decodeToken(token, cryptkey);
    if(Len(stoken)) {
      // stoken = validateToken(stoken, signkey);
    }
    return stoken;
    </cfscript>
  
  </cffunction>
  
  
  <cffunction name="decodeToken" access="public" output="no" returnType="string"
    description="Decodes the given token string.">
    <cfargument name="stoken" required="yes" type="string">
    <cfargument name="cryptkey" required="no" type="string" default="">
    <cfscript>
    var iv = ''; var crypted = ''; var decoded_token = ''; var token_bytes = '';

    // use cryptKey instance variable if not passed in
    if(Len(cryptkey) eq 0) {
      cryptkey = Variables.cryptKey;
      if(Len(cryptkey) eq 0) {
        fatal("Error: decodeToken: Secret key was not set. Aborting.");
      }
    }
    
    // URL-unescape and base64 decode
    token_bytes = BinaryDecode(URLDecode(stoken), "base64");
    if(ArrayLen(token_bytes) lte 16 or ((ArrayLen(token_bytes) mod 16) neq 0)) {
      debug("Error: decodeToken: Attempted to decode invalid token.");
    }
    
    // extract IV from the first 16 bytes of the string
    iv = BinaryLeft(token_bytes, 16);
    crypted = BinaryRight(token_bytes, ArrayLen(token_bytes) - 16);

    // decrypt using the encryption key
    decoded_token = DecryptBinary(crypted, cryptkey, "AES/CBC/PKCS5Padding", iv);
    return ToString(decoded_token);    
    </cfscript>
  </cffunction>
  
  <cffunction name="derive" access="public" output="no" returnType="string"
    description="Derives the key, given the secret key and prefix 
                 as described in the Web Authentication SDK documentation.">
    <cfargument name="secret" required="yes" type="string">
    <cfargument name="prefix" required="yes" type="string">
    <cfscript>
    var key = prefix & secret;
    var digest = BinaryDecode(Hash(key, "SHA-256"), "hex");
    var crypt_key = BinaryLeft(digest, 16);
    return ToBase64(crypt_key);
    </cfscript>
  </cffunction>
  
  <!--- helpers --->
  <cffunction name="parse" access="public" output="no" returnType="struct"
    description="parse query string and returns a struct">
    <cfargument name="input" required="yes" type="string">
    <cfscript>
    var pairs = StructNew(); var k = ''; var v = '';
    var inputs = ''; var i = 1;
    
    if( Len(input) eq 0 ) {
      debug("Error: parse: Null input.");
      return StructNew();
    }
    
    inputs = ListToArray(input, "&");
    
    for(i = 1; i lte ArrayLen(inputs); i = i + 1) {
      pair = inputs[i];
      if( Find("=", pair) ) {
        k = ListFirst(pair, "=");
        v = ListRest(pair, "=");
        pairs[k] = v;
      }
    }
    
    return pairs;
    </cfscript>
  </cffunction>
  
  
</cfcomponent>