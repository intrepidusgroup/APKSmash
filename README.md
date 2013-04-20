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


Version History
===============

v2.50 - MAKE SURE TO USE IGLogger > 2.50 if JonestownThisAPK is TRUE
	(lots of new calls added and you'll need the updated logger class)
	Added new traces for Jonestown: SQL, SharedPrefs, Intents
	Better support for virtual calls 
	Ability to skip certain packages (see 'skip_classes')
	fixed string compare for objects (sometime the wrong type got passed)