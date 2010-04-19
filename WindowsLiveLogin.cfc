<cfcomponent>

  <cffunction name="decodeToken" access="public" output="no" returnType="string"
    description="Decodes the given token string." 
    hint="First, the string is URL-unescaped and base64 decoded.
          Second, the IV is extracted from the first 16 bytes of the string.
          Finally, the string is decrypted using the encryption key.">
    <cfargument name="stoken" required="yes" type="string">
    <cfargument name="crypt_key" required="yes" type="string">
    <cfscript>  
    token_bytes = BinaryDecode(URLDecode(stoken), "base64");

    Arrays = CreateObject("java", "java.util.Arrays");
    iv = Arrays.copyOf(token_bytes, 16);
    crypted = Arrays.copyOfRange(token_bytes, 16, ArrayLen(token_bytes));

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
    keyLen = 16;
    key = prefix & secret;
    digest = BinaryDecode(Hash(key, "SHA-256"), "hex");
    Arrays = CreateObject("java", "java.util.Arrays");
    crypt_key = Arrays.copyOf(digest, keyLen);
    return ToBase64(crypt_key);
    </cfscript>
  </cffunction>
  
</cfcomponent>