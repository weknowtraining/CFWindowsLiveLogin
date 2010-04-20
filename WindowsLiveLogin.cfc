<cfcomponent displayname="Windows Live Login" 
  description="Windows Live ID Web Authentication SDK">

  <cfinclude template="udf_binary.cfm">

  <!--- constructor --->
  <cffunction name="init" access="public" output="no" returnType="WindowsLiveLogin"
    description="Initialize the WindowsLiveLogin module">
    <!--- private variables --->
    <cfset Variables.log = false>
    
    <cfreturn This>
  </cffunction>

  <!--- debugging --->
  <cffunction name="setDebug" access="public" output="no" returnType="void">
    <cfargument name="logenabled" required="yes" type="boolean">
    <cfset Variables.log = logenabled>
  </cffunction>
  
  <cffunction name="debug" access="private" output="no" returnType="void">
    <cfargument name="error" required="yes" type="string">
    <cfargument name="error_type" required="no" type="string" default="Warning">
    <cfif Variables.log>
      <cflog text="#error#" file="WindowsLiveLogin" type="#error_type#">
    </cfif>
  </cffunction>

  <cffunction name="fatal" access="private" output="no" returnType="void">
    <cfargument name="error" required="yes" type="string">
    <cfset debug(error, "Fatal")>
    <cfthrow type="WLLError" message="#error#">
  </cffunction>

  <cffunction name="decodeToken" access="public" output="no" returnType="string"
    description="Decodes the given token string." 
    hint="First, the string is URL-unescaped and base64 decoded.
          Second, the IV is extracted from the first 16 bytes of the string.
          Finally, the string is decrypted using the encryption key.">
    <cfargument name="stoken" required="yes" type="string">
    <cfargument name="crypt_key" required="yes" type="string">
    <cfscript>  
    token_bytes = BinaryDecode(URLDecode(stoken), "base64");

    if(ArrayLen(token_bytes) lte 16 or ((ArrayLen(token_bytes) mod 16) neq 0)) {
      debug("Error: decodeToken: Attempted to decode invalid token.");
    }

    iv = BinaryLeft(token_bytes, 16);
    crypted = BinaryRight(token_bytes, ArrayLen(token_bytes) - 16);

    decoded_token = DecryptBinary(crypted, crypt_key, "AES/CBC/PKCS5Padding", iv);
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
  
</cfcomponent>