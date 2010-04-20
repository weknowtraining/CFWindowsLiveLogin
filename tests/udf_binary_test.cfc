<cfcomponent displayname="BinaryTest" extends="mxunit.framework.TestCase">

  <cfinclude template="../udf_binary.cfm">
  
  <cfscript>
  function setup() {
    bytes = BinaryDecode("deadbeef", "hex");  // encodes to 4 bytes
  }
  
  function testBinaryLeft() {    
    var new_bytes = ''; var hex = '';
    new_bytes = BinaryLeft(bytes, 3);
    assertEquals(3, ArrayLen(new_bytes), "took three bytes");
    hex = BinaryEncode(new_bytes, "hex");
    assertEquals("deadbe", hex, "the first three bytes");
  }
  
  function testBinaryMid() {
    var new_bytes = ''; var hex = '';
    new_bytes = BinaryMid(bytes,2,2);
    assertEquals(2, ArrayLen(new_bytes), "took two bytes");
    hex = BinaryEncode(new_bytes, "hex");
    assertEquals("adbe", hex, "two middle bytes");
  }
  
  function testBinaryRight() {
    var new_bytes = ''; var hex = '';
    new_bytes = BinaryRight(bytes,2);
    assertEquals(2, ArrayLen(new_bytes), "took two bytes");
    hex = BinaryEncode(new_bytes, "hex");
    assertEquals("beef", hex, "last two bytes");
  }
  
  // edge cases (Left)
  function testBinaryLeftOfLength() {    
    var new_bytes = BinaryLeft(bytes, ArrayLen(bytes));
    assertEquals(bytes, new_bytes);
  }
  
  function testBinaryLeftOverLength() {    
    var new_bytes = BinaryLeft(bytes, ArrayLen(bytes) + 1);
    assertEquals(bytes, new_bytes);
  }
  
  function testBinaryLeftOfZero() {    
    var new_bytes = BinaryLeft(bytes, 0);
    assertEquals(0, ArrayLen(new_bytes), "took no bytes");
  }

  function testBinaryLeftOfNegative() {    
    var new_bytes = BinaryLeft(bytes, -1);
    assertEquals(0, ArrayLen(new_bytes), "took no bytes");
  }
  
  // edge cases (Right)
  function testBinaryRightOfLength() {    
    var new_bytes = BinaryRight(bytes, ArrayLen(bytes));
    assertEquals("deadbeef", BinaryEncode(new_bytes, "hex"));
  }
  
  function testBinaryRightOverLength() {    
    var new_bytes = BinaryRight(bytes, ArrayLen(bytes) + 1);
    assertEquals("deadbeef", BinaryEncode(new_bytes, "hex"));
  }
  
  function testBinaryRightOfZero() {    
    var new_bytes = BinaryRight(bytes, 0);
    assertEquals(0, ArrayLen(new_bytes), "took no bytes");
  }
  
  function testBinaryRightOfNegative() {    
    var new_bytes = BinaryRight(bytes, -1);
    assertEquals(0, ArrayLen(new_bytes), "took no bytes");
  }
  
  // edge cases (Mid)
  function testBinaryMidOfLength() {    
    var new_bytes = BinaryMid(bytes, 1, ArrayLen(bytes));
    assertEquals("deadbeef", BinaryEncode(new_bytes, "hex"));
  }
  
  function testBinaryMidOverLength() {    
    var new_bytes = BinaryMid(bytes, 3, ArrayLen(bytes));
    assertEquals("beef", BinaryEncode(new_bytes, "hex"));
  }
  
  function testBinaryMidOfNegative() {
    var new_bytes = ''; 
    expectException("InvalidFunctionArgException");  // new to mxunit trunk (> 1.08)
    new_bytes = BinaryMid(bytes, -1, ArrayLen(bytes));
  }
  </cfscript>

</cfcomponent>