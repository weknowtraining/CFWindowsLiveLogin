<cfcomponent displayname="WindowsLiveLoginTest" extends="mxunit.framework.TestCase">

  <cfscript>
  function setup() {
    wll = createObject("component","WindowsLiveLogin").init();
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
    live = createObject("component","WindowsLiveLogin").init(
      appid="00167FFE80002701", secret="ApplicationKey123", securityalogrithm="wsignin1.0");
    assertEquals("00167FFE80002701", live.getAppId());
    assertEquals("wsignin1.0", live.getSecurityAlgorithm());
  }
  

  
  </cfscript>

</cfcomponent>