# logback-android is configured by reflection.
-keep class ch.qos.logback.** { *; }
-dontwarn ch.qos.logback.**
-dontwarn javax.naming.**
-dontwarn javax.mail.**

# Read by name to list the accounts a key returns, while yubikit's own list can fail (see Accounts.kt).
-keepclassmembers class com.yubico.yubikit.fido.client.MultipleAssertionsAvailable {
    java.util.List assertions;
}
