# Windows Live ID Web Authentication SDK 1.2

Incomplete port to Adobe ColdFusion 8 and 9.

## Usage:

    live = CreateObject("component", "WindowsLiveLogin").init(appid=Request.LiveAppId, secret=Request.LiveSecret);
    live.setDebug(true);
    user = live.processLogin(form);
    // user.uid


## Sun Unlimited Strength Jurisdiction Policy Files

    C:\ColdFusion8\runtime\jre\lib\security


