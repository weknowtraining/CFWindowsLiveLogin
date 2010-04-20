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
    var token = live.decodeToken(stoken); assertEquals("appid=000000004402df21&uid=cb6758ecf06821bade130e77e1702c4b&ts=1271446184&sig=dyvoqxchaxa5rndtismzzij/ipvlddkf03nthhxazuc=", URLDecode(token)); // not the best thing to test
  }
  
  function testDecodeNoKey() {
    expectException("WLLError");
    wll.decodeToken(stoken);
  }
  
  </cfscript>

</cfcomponent>