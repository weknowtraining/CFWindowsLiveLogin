<!---
Mimics the CFTHROW tag for CF8 or earlier.

@param Type      Type for exception. (Optional)
@param Message      Message for exception. (Optional)
@param Detail      Detail for exception. (Optional)
@param ErrorCode      Error code for exception. (Optional)
@param ExtendedInfo      Extended Information for exception. (Optional)
@param Object      Object to throw. (Optional)
@return Does not return a value. 
@author Raymond Camden (ray@camdenfamily.com) 
@version 1, October 15, 2002 
--->
<cffunction name="throw" output="false" returnType="void" hint="CFML Throw wrapper">
  <cfargument name="detail" type="string" required="false" default="" 
    hint="Detail for Exception">
  <cfargument name="errorCode" type="string" required="false" default="" 
    hint="Error Code for Exception">
  <cfargument name="extendedInfo" type="string" required="false" default=""
    hint="Extended Info for Exception">
  <cfargument name="message" type="string" required="false" default="" 
    hint="Message for Exception">
  <cfargument name="object" type="any" hint="Object for Exception">
  <cfargument name="type" type="string" required="false" default="Application" 
    hint="Type for Exception">

  <cfif not isDefined("object")>
    <cfthrow type="#type#" message="#message#" detail="#detail#" errorCode="#errorCode#"
      extendedInfo="#extendedInfo#">
  <cfelse>
    <cfthrow object="#object#">
  </cfif>    
</cffunction>

