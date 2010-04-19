<cfcomponent>

  <cfscript>  
  function decodeToken(stoken, crypt_key) {
    token_bytes = BinaryDecode(URLDecode(stoken), "base64");

    Arrays = CreateObject("java", "java.util.Arrays");
    iv = Arrays.copyOf(token_bytes, 16);
    crypted = Arrays.copyOfRange(token_bytes, 16, ArrayLen(token_bytes));

    decoded_token = DecryptBinary(crypted, crypt_key, "AES/CBC/PKCS5Padding", iv);
    return ToString(decoded_token);
  }

  function derive(secret, prefix) {
    keyLen = 16;
    key = prefix & secret;
    digest = BinaryDecode(Hash(key, "SHA-256"), "hex");
    Arrays = CreateObject("java", "java.util.Arrays");
    crypt_key = Arrays.copyOf(digest, keyLen);
    return ToBase64(crypt_key);
  }
  </cfscript>

</cfcomponent>