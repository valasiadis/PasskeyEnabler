/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package space.valasiadis.passkeyenabler

import android.content.Context
import android.content.pm.PackageManager
import android.content.pm.Signature
import android.util.Base64
import androidx.core.content.edit
import androidx.core.net.toUri
import androidx.credentials.provider.CallingAppInfo
import org.json.JSONArray
import org.json.JSONObject
import java.io.IOException
import java.net.URL
import java.security.MessageDigest
import javax.net.ssl.HttpsURLConnection

/**
 * Who asked for a passkey, and so on whose behalf the security key signs.
 *
 * WebAuthn binds a passkey to the origin that asked for it, and a provider has to vouch for that
 * origin itself. A browser names the website it is asking for; that is only believed of a browser
 * the user has said to trust, recognised by its signing certificate. Any other app is its own
 * origin (`android:apk-key-hash:…`), and may only ask for the passkeys of a website that names it
 * as its app in its Digital Asset Links, as Google's own provider requires.
 */
internal class Caller(
    /** The app, by the name the user knows it by. */
    val label: String,
    /** The origin written into the client data the key signs. */
    val origin: String,
    /** What the RP ID is checked against: the website's host, or the RP ID an app was cleared for. */
    val effectiveDomain: String,
    /** The hash of client data a browser built itself, signed as it is in place of client data of our own. */
    val clientDataHash: ByteArray?,
) {
    /** Why a caller was not let through, said to the user as it stands. */
    class Refused(
        override val message: String,
    ) : Exception(message)

    /** A browser the user has yet to say whether to trust. */
    class UntrustedBrowser(
        val label: String,
        val packageName: String,
        val fingerprint: String,
    ) : Exception()

    companion object {
        private const val LOGIN_CREDS = "delegate_permission/common.get_login_creds"
        private const val MAX_ASSET_LINKS_BYTES = 512 * 1024
        private const val TIMEOUT_MS = 8_000

        /**
         * Works out who [info] is. Blocks on the network for an app's asset links, so is called off
         * the main thread.
         *
         * @throws UntrustedBrowser for a browser to be asked about first
         * @throws Refused for a caller not let through
         */
        fun resolve(
            context: Context,
            info: CallingAppInfo,
            rpId: String?,
            clientDataHash: ByteArray?,
        ): Caller {
            val label = label(context, info.packageName)
            val signer = currentSigner(info) ?: throw Refused(context.getString(R.string.caller_unknown))
            val fingerprint = fingerprint(signer)
            if (info.isOriginPopulated()) {
                if (!TrustedBrowsers(context).isTrusted(info.packageName, fingerprint)) {
                    throw UntrustedBrowser(label, info.packageName, fingerprint)
                }
                val origin =
                    runCatching { info.getOrigin(allowlist(info.packageName, fingerprint)) }.getOrNull()
                        ?: throw Refused(context.getString(R.string.caller_unknown))
                val host =
                    origin.toUri().takeIf { it.scheme == "https" }?.host
                        ?: throw Refused(context.getString(R.string.request_invalid))
                return Caller(label, origin.trimEnd('/'), host, clientDataHash)
            }
            // An app speaks for itself, and only for a website that says so.
            val rp = rpId?.takeIf { it.isNotEmpty() } ?: throw Refused(context.getString(R.string.request_invalid))
            val linked =
                try {
                    assetLinksAllow(rp, info.packageName, fingerprint)
                } catch (e: IOException) {
                    throw Refused(context.getString(R.string.app_link_unreachable, label, rp))
                }
            if (!linked) throw Refused(context.getString(R.string.app_not_linked, label, rp))
            val keyHash = Base64.encodeToString(sha256(signer.toByteArray()), Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
            return Caller(label, "android:apk-key-hash:$keyHash", rp, null)
        }

        fun label(
            context: Context,
            packageName: String,
        ): String = try {
            val pm = context.packageManager
            pm.getApplicationLabel(pm.getApplicationInfo(packageName, 0)).toString()
        } catch (_: PackageManager.NameNotFoundException) {
            packageName
        }

        /** The certificate the app is signed with now: the last of its rotations, or its first signer. */
        private fun currentSigner(info: CallingAppInfo): Signature? {
            val signing = info.signingInfo
            return if (signing.hasMultipleSigners()) {
                signing.apkContentsSigners.firstOrNull()
            } else {
                signing.signingCertificateHistory.lastOrNull()
            }
        }

        private fun fingerprint(signature: Signature): String = sha256(signature.toByteArray()).joinToString(":") { "%02X".format(it) }

        private fun sha256(bytes: ByteArray): ByteArray = MessageDigest.getInstance("SHA-256").digest(bytes)

        /** The one browser trusted, in the form the platform checks a caller's origin against. */
        private fun allowlist(
            packageName: String,
            fingerprint: String,
        ): String = JSONObject()
            .put(
                "apps",
                JSONArray().put(
                    JSONObject()
                        .put("type", "android")
                        .put(
                            "info",
                            JSONObject()
                                .put("package_name", packageName)
                                .put(
                                    "signatures",
                                    JSONArray().put(
                                        JSONObject()
                                            .put("build", "release")
                                            .put("cert_fingerprint_sha256", fingerprint),
                                    ),
                                ),
                        ),
                ),
            ).toString()

        /**
         * Whether the website at [domain] lets [packageName], signed with [fingerprint], use its
         * passkeys: a statement in its asset links granting it the sign-in relation.
         */
        private fun assetLinksAllow(
            domain: String,
            packageName: String,
            fingerprint: String,
        ): Boolean {
            val connection = URL("https", domain, "/.well-known/assetlinks.json").openConnection() as HttpsURLConnection
            try {
                connection.instanceFollowRedirects = false
                connection.connectTimeout = TIMEOUT_MS
                connection.readTimeout = TIMEOUT_MS
                connection.setRequestProperty("Accept", "application/json")
                if (connection.responseCode != HttpsURLConnection.HTTP_OK) return false
                val body =
                    connection.inputStream.use { stream ->
                        val bytes = stream.readNBytes(MAX_ASSET_LINKS_BYTES + 1)
                        if (bytes.size > MAX_ASSET_LINKS_BYTES) return false
                        String(bytes, Charsets.UTF_8)
                    }
                val statements = runCatching { JSONArray(body) }.getOrNull() ?: return false
                return (0 until statements.length()).any { index ->
                    val statement = statements.optJSONObject(index) ?: return@any false
                    val relations = statement.optJSONArray("relation") ?: return@any false
                    val target = statement.optJSONObject("target") ?: return@any false
                    val fingerprints = target.optJSONArray("sha256_cert_fingerprints") ?: return@any false
                    (0 until relations.length()).any { relations.optString(it) == LOGIN_CREDS } &&
                        target.optString("namespace") == "android_app" &&
                        target.optString("package_name") == packageName &&
                        (0 until fingerprints.length()).any { fingerprints.optString(it).equals(fingerprint, ignoreCase = true) }
                }
            } finally {
                connection.disconnect()
            }
        }
    }
}

/** The browsers the user has said may name the website they ask for, each by its signing certificate. */
internal class TrustedBrowsers(
    context: Context,
) {
    private val prefs = context.getSharedPreferences("trusted_browsers", Context.MODE_PRIVATE)

    /** Package name to certificate fingerprint. */
    fun all(): Map<String, String> = prefs.all.mapNotNull { (key, value) -> (value as? String)?.let { key to it } }.toMap()

    fun isTrusted(
        packageName: String,
        fingerprint: String,
    ): Boolean = prefs.getString(packageName, null) == fingerprint

    fun trust(
        packageName: String,
        fingerprint: String,
    ) {
        prefs.edit { putString(packageName, fingerprint) }
    }

    fun forget(packageName: String) {
        prefs.edit { remove(packageName) }
    }
}
