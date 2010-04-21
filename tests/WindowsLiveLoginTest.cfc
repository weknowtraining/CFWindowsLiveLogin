<cfcomponent displayname="WindowsLiveLoginTest" extends="mxunit.framework.TestCase">

  <cfscript>
  function setup() {
    wll = createObject("component","WindowsLiveLogin").init();  // to test setters separately
    
    live = createObject("component","WindowsLiveLogin").init(
      appid="000000004402DF21",
      secret="oaFATANGccQOcm2nHcmqxX3vYuclAeTx"); // real credentials
    
    stoken = "ZDvvs6mFYyWrXGQESz20azlNHxeySRqT5kQkA%2FgCDXmByrkmt9In9wFtpv8SPxl%2BshCCmUe"
           & "VODM0NV3odWZBhdzCHyAMWKUtVhwqCOxwjpQlvQGXFitvk9ozzIRAB9GXMVIOVvsx3Vmk7NgjjL"
           & "Ea56JQlG3ZiV0e3ksjjOyH1%2BC8%2Bly3tjrJED94khVmZJM3";

    decoded_token = "appid=000000004402DF21&uid=cb6758ecf06821bade130e77e1702c4b&ts=1271446184"
                  & "&sig=dYvOqXcHaXA5rnDTisMzzij/IPVlDdkf03NTHhxAzuc=";
    
    fs = StructNew();
    fs.action = "login";    // form fields
    fs.stoken = stoken;
    fs.appctx = "myContext";
  }
  
  // AppId
  function testGoodAppId() {
    var appid = "00167FFE80002701";
    wll.setAppId(appid);
    assertEquals(appid, wll.getAppId());
  }

  function testBadAppId() {
    expectException("WLLError");
    wll.setAppId("12!(*&)##ab");
  }

  function testEmptyAppId() {
    expectException("WLLError");
    wll.setAppId("");
  }
  
  function testGetBeforeSetAppId() {
    expectException("WLLError");
    wll.getAppId();
  }
  
  // Secret
  function testSetSecret() {
    wll.setSecret("ApplicationKey123");
    // then what?
  }
  
  function testSetSecretTooShort() {
    expectException("WLLError");
    wll.setSecret("tooshort");
  }
  
  // Security Algorithm
  function testSetSecurityAlgorithm() {
    wll.setSecurityAlgorithm("something");
    assertEquals("something", wll.getSecurityAlgorithm());
  }
  
  function testDefaultSecurityAlgorithm() {
    assertEquals("wsignin1.0", wll.getSecurityAlgorithm());
  }
  
  // constructor
  function testInit() {
    var wllinit = createObject("component","WindowsLiveLogin").init(
      appid="00167FFE80002701", secret="ApplicationKey123", securityalogrithm="wsignin1.0");
    assertEquals("00167FFE80002701", wllinit.getAppId());
    assertEquals("wsignin1.0", wllinit.getSecurityAlgorithm());
  }
  
  // decode
  function testDecode() {
    var token = live.decodeToken(stoken); assertEquals(decoded_token, URLDecode(token)); // not the best thing to test
  }
  
  function testDecodeNoKey() {
    expectException("WLLError");
    wll.decodeToken(stoken);
  }
  
  // parse
  function testParse() {
    q = "appid=1&uid=2&ts=3&sig=x/y=";
    s = live.parse(q);
    assertEquals(4, StructCount(s));
    assertEquals("1", s.appid);
    assertEquals("2", s.uid);
    assertEquals("3", s.ts);
    assertEquals("x/y=", s.sig);
  }
  
  // signToken
  function testSignToken() {
    var hmac = live.signToken("appid=000000004402DF21&uid=cb6758ecf06821bade130e77e1702c4b&ts=1271446184");
    assertEquals("dYvOqXcHaXA5rnDTisMzzij/IPVlDdkf03NTHhxAzuc=", hmac);
  }
  
  // validateToken
  function testValidateToken() {
    var t = live.validateToken(decoded_token);
    assertEquals(decoded_token, t);
  }
  
  // processToken
  function testProcessToken() {
    var user = live.processToken(stoken);
    assertTrue(user.valid);
    assertEquals("cb6758ecf06821bade130e77e1702c4b", user.uid);
    assertEquals(1271446184, user.timestamp);
  }
  
  function testProcessTokenBadAppId() {
    live.setAppId("somethingelse");
    var user = live.processToken(stoken);
    assertFalse(user.valid);
    assertTrue(FindNoCase("did not match application ID", user.error), "should match error message");
  }
  
  function testProcessTokenEmpty() {
    var user = live.processToken("");
    assertFalse(user.valid);
  }
  
  // processLogin
  function testProcessLogin() {
    var user = live.processLogin(fs);
    assertTrue(user.valid);
  }
  
  function testProcessLoginNoAction() {
    var user = '';
    StructDelete(fs, "action");
    user = live.processLogin(fs);
    assertFalse(user.valid, "should not be valid");
    assertTrue( FindNoCase("No action", user.error), "should match error message");
  }
  
  function testProcessLoginOtherAction() {
    var user = '';
    fs.action = "logout";
    user = live.processLogin(fs);
    assertFalse(user.valid, "should not be valid");
    assertTrue( FindNoCase("action ignored", user.error), "should match error message");
  }
  
  </cfscript>

</cfcomponent>