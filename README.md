# Passkey Enabler

Use the passkeys on a FIDO2 security key (a YubiKey, for example) to sign in to websites and
apps on Android: tap the key on the back of the phone, or plug it in.

The app is a passkey provider. When a site asks for a passkey, Android's passkey sheet offers
**Security key**. Pick it, enter the key's PIN, tap the key, and you're signed in. It works the same way
when a site creates a passkey.

Built for the Pixel 10 Pro XL running GrapheneOS, and should work on other Android 14+ phones too.
It needs no Google Play Services. It is built on Yubico's
[yubikit-android](https://github.com/Yubico/yubikit-android) library.

## Why

Yubico's own *YubiKey Passkey Enabler* does the same job, but on GrapheneOS it fails at a
common case: when the key holds passkeys for **two or more accounts on the same site** and you
sign in without typing a username, its account picker says *"Select a passkey to login
(0 available)"* and stays empty, so you can't sign in at all.

That happens because many keys don't return the accounts' display names (CTAP only promises the
account ID), and the yubikit-android library it uses treats a missing display name as an
error. The app then swallows that error and shows an empty list.

Passkey Enabler reads the account list the way the specification allows: only the ID is
required, and an account without a display name is shown by its user name, or by its ID if it
has neither. Once a yubikit-android release handles this itself, the app will rely on that.

## Features

- **Sign in and create passkeys** on a security key over **NFC** or **USB**.
- **Usernameless sign-in.** When the key holds passkeys for several accounts on one site, you
  choose one from a list. Keys that don't return a display name still list each
  account by its name or ID.
- **PIN first.** The PIN is asked for before the key, so over NFC you only tap once.
- **Clear messages** for a wrong PIN (with the tries left), a locked PIN, a key with no passkey for
  the site, a full key, and a key lifted too soon.
- The PIN sheet is hidden from screenshots and screen recordings.

## Install with Obtainium (recommended)

[Obtainium](https://github.com/ImranR98/Obtainium) installs apps straight from their GitHub
releases and keeps them updated.

1. **Install Obtainium** from its [GitHub releases](https://github.com/ImranR98/Obtainium/releases)
   (or from F-Droid / IzzyOnDroid).
2. Open Obtainium, tap **Add app**, and paste this repository's URL:
   ```
   https://github.com/valasiadis/PasskeyEnabler
   ```
   Leave the source on **GitHub** and the other options at their defaults.
3. Tap **Add**, then **Install**. The first time, Android asks you to allow Obtainium to
   install apps: on GrapheneOS that's *Settings → Apps → Obtainium → Install unknown apps*.

Obtainium checks for new releases in the background and offers updates. You can also pull
down on its app list to check right away.

**Check the signature (optional).** Every release lists the signing certificate's SHA-256
fingerprint in its notes. To confirm that the APK you installed came from this repository,
compare that fingerprint with the one [AppVerifier](https://github.com/soupslurpr/AppVerifier)
shows for Passkey Enabler.

> If you previously installed a build you made yourself, uninstall it first. It's signed with
> a different key, and Android refuses to update an app across signing keys.

### Without Obtainium

Download `PasskeyEnabler-vX.Y.Z.apk` from the [Releases](https://github.com/valasiadis/PasskeyEnabler/releases)
page and open it on the phone. You'll have to repeat this for every update.

## Setting it up

1. Open **Passkey Enabler** and tap **Open passkey settings**. Or go to
   *Settings → Passwords, passkeys & accounts* yourself.
2. Turn on **Passkey Enabler** (shown as **Security key**).
3. Your security key needs a PIN. If it has none, set one with the
   [Yubico Authenticator](https://www.yubico.com/products/yubico-authenticator/) or `ykman fido access change-pin`.

## Using it

- On a website or in an app, choose to sign in with a passkey, then pick **Security key** in
  Android's sheet.
- Enter the PIN, then hold the key to the back of the phone (or plug it in) until the tick
  appears. A plugged-in YubiKey asks you to touch it.
- If the key holds more than one account for the site, choose one from the list.
- **The first time a browser asks** (Vanadium, Firefox, Chrome, …), you're asked whether to
  trust it as a browser. See [Who may ask for a passkey](#who-may-ask-for-a-passkey).

## Who may ask for a passkey

A passkey belongs to one website, and the provider has to know which website is asking.

- **Browsers** say which website they're asking for. Passkey Enabler only believes that from a
  browser you have trusted. You're asked the first time a browser asks, and the trust is tied
  to that browser's signing certificate, so a different app under the same name isn't trusted.
  Trusted browsers are listed in the app, and tapping one forgets it.
- **Other apps** may only use a website's passkeys if that website names the app as its own in
  its `/.well-known/assetlinks.json` (the `delegate_permission/common.get_login_creds`
  relation), the same rule Google's own passkey provider follows.

## Permissions and privacy

| Permission | Why |
| --- | --- |
| NFC | To talk to a security key held to the phone. |
| Internet | Only to read a website's `assetlinks.json` when an app (not a browser) asks for its passkeys. |

Nothing else is sent anywhere, and there are no analytics. The PIN is held in memory only for one
sign-in and is never stored. Passkeys never leave the security key. The only thing the app
stores is the list of browsers you trusted.

## Building from source

Requirements: JDK 21 (Gradle downloads one if needed) and the Android SDK with platform 37.

```sh
./gradlew assembleDebug        # app/build/outputs/apk/debug/app-debug.apk
./gradlew installDebug         # build and install on a connected phone
```

Debug builds install as a separate app, **Passkey Enabler (test)**
(`space.valasiadis.passkeyenabler.debug`), so they don't collide with the release version from
Obtainium.

## License

Copyright (C) 2026 Emanuel Valasiadis

Passkey Enabler is free software: you can redistribute it and/or modify it under the terms of
the GNU General Public License as published by the Free Software Foundation, version 3 of
the License.

The sheets the app shows come from a fork of
[Android Password Store](https://github.com/android-password-store/Android-Password-Store)
(GPL-3.0-only), and their files keep that project's copyright notice. yubikit-android is
licensed under the Apache License 2.0.

It is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even
the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
[LICENSE](LICENSE) file for details.
