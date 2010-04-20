<cfif ListFirst(Server.coldfusion.productversion) lt 9>
  <cfinclude template="udf_throw.cfm">
</cfif>

<!--- some helpers for working with binary fields --->
<cfscript>
Arrays = CreateObject("java", "java.util.Arrays");

function BinaryLeft(bytes, count)
{
  if(count gte ArrayLen(bytes)) {
    return bytes;
  }
  else {
    if(count lt 0) { count = 0; }
    return Arrays.copyOf(bytes, count); 
  }
}

// start (1-based), count
function BinaryMid(bytes, start, count)
{
  var pos = start - 1; // adjust for base-1 (CF) vs. base-0 (Java)
  var end = pos + count;  // end point is exclusive
  if(start lt 1) { 
    throw(type="InvalidFunctionArgException", message="BinaryMid start parameter must be a positive integer");
  }
  if(end gt ArrayLen(bytes)) { end = ArrayLen(bytes); }
  return Arrays.copyOfRange(bytes, pos, end);
}

function BinaryRight(bytes, count)
{
  if(count gte ArrayLen(bytes)) {
    return bytes;
  }
  else {
    if(count lt 0) { count = 0; }
    return Arrays.copyOfRange(bytes, ArrayLen(bytes) - count, ArrayLen(bytes));
  }
}
</cfscript>