<!--- View this page to run the tests
      Requires MXUnit in your webroot, download from http://mxunit.org/
      (using some features from trunk, > 1.08)
--->
<cfparam name="URL.output" default="extjs">

<cfscript>
testSuite = createObject("component","mxunit.framework.TestSuite").TestSuite();
testSuite.addAll("udf_binary_test");
results = testSuite.run();
</cfscript>

<cfoutput>#results.getResultsOutput(URL.output)#</cfoutput>
