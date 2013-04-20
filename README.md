APKSmash
========

Search for interesting things in an APK, inject logging (if desired), and add
comments for referenced strings.


Usage
=====

Use APKTool to decompile an APK, then run this in the output directory. This
will create an "apk-ig-info.txt" file with the results and modify files in
the "smali" directory. For JonesTown modifications, make sure to include
"iglogger.smali" into the root of the "smali" directory.


JonesTown
=========

JonesTown will massacre your APK.

You APK will slow down, may be come sleepy, and might die... but it might
be worth it.

JonesTown injects a lot of automated debug statements into the smali code. 
There's  a (decent) chance may cause the APK to have build errors or throw 
runtime errors. I've tried to avoid this as much as possible, but I probably
haven't found all the edge cases yet.

When this works though, its a very easy way to watch logcat and see what
the app is doing. Here's a few highlights:

 + Logs out the package name and method when a method is entered (Handy for tracing through obfuscated apps)
 + Logs SQL queries the app makes to local SQLite databases
 + Logs Intent messages before being sent/broadcast to Activities, Services, Receivers
 + Logs Intent messages when received by Activities, Services, or Receivers
 + Logs URL used to open a Webview (sorry, can't track URLs after that yet)
 + Logs requests/response to SharedPreferences string objects (may add more types later)
 + Logs some types of JSON and HTTP requests (looking to add more)
 + Logs the values of two strings that are compared 
 + Logs the Boolean result from methods which return only True/False

To enable this, set "JonestownThisAPK = True" in the script. You will also
need to include "iglogger.smali" into the root of the "smali" directory 
(look for our IGLogger repo on GitHub). It's important to use the most
up-to-date IGLogger code or you will probably get runtime errors about methods
not being found in iglogger.

You can also have JonesTown skip specific packages by using "skip_classes".
Some packages seem to just be distracting and not useful to log while 
reversing. Use this to cut down on the junk getting log.

APK-IG-INFO
===========

The "apk-ig-info.txt" will report which classes contain calls to items you
might be interested in if you're reversing the APK. This includes some simple
things like "debug" variables or methods, hard code URLs and IP addresses,
and possible logging calls. It will also try to identify classes that use
external storage or access local files.

Add your own checks to either the "searchterms" or "regexsearchterms" at the
top of the file.



Version History
===============

v2.50 

 + MAKE SURE TO USE IGLogger > 2.50 if JonestownThisAPK is TRUE
 + (lots of new calls added and you'll need the updated logger class)
 + Added new traces for JonesTown: SQL, SharedPrefs, Intents
 + Better support for virtual calls 
 + Ability to skip certain packages (see 'skip_classes')
 + Fixed string compare for objects (sometime the wrong type got passed)