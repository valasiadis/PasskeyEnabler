/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package space.valasiadis.passkeyenabler

import android.content.Intent
import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.credentials.CreatePublicKeyCredentialRequest
import androidx.credentials.CreatePublicKeyCredentialResponse
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetPublicKeyCredentialOption
import androidx.credentials.exceptions.CreateCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.domerrors.InvalidStateError
import androidx.credentials.exceptions.domerrors.NotAllowedError
import androidx.credentials.exceptions.publickeycredential.CreatePublicKeyCredentialDomException
import androidx.credentials.exceptions.publickeycredential.GetPublicKeyCredentialDomException
import androidx.credentials.provider.CallingAppInfo
import androidx.credentials.provider.PendingIntentHandler
import androidx.lifecycle.lifecycleScope
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.yubico.yubikit.fido.client.MultipleAssertionsAvailable
import com.yubico.yubikit.fido.client.clientdata.ClientDataProvider
import com.yubico.yubikit.fido.webauthn.PublicKeyCredential
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialCreationOptions
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialRequestOptions
import com.yubico.yubikit.fido.webauthn.SerializationType
import com.yubico.yubikit.fido.webauthn.UserVerificationRequirement
import space.valasiadis.passkeyenabler.ui.AccountPicker
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import org.slf4j.LoggerFactory
import kotlin.coroutines.resume
import androidx.credentials.PublicKeyCredential as CredentialManagerPasskey

/**
 * What the system opens once "Security key" is picked for a passkey: works out who is asking, runs
 * the request on the key in the sheets, and hands the passkey, or why there is none, back.
 *
 * It has nothing of its own to show. It stands transparent over the app that asked, and only its
 * sheets rise over that.
 */
class PasskeyActivity : AppCompatActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (savedInstanceState != null) {
            // Rebuilt part-way: the operation went with the old screen, and the request with it.
            finishCancelled()
            return
        }
        lifecycleScope.launch {
            try {
                when (intent.action) {
                    ACTION_CREATE -> create()
                    ACTION_GET -> get()
                    else -> finish()
                }
            } catch (e: Exception) {
                logger.error("Passkey request failed", e)
                fail(getString(R.string.request_invalid), excluded = false)
            }
        }
    }

    private val isCreate get() = intent.action == ACTION_CREATE

    private suspend fun create() {
        val request = PendingIntentHandler.retrieveProviderCreateCredentialRequest(intent)
        val passkeyRequest = request?.callingRequest as? CreatePublicKeyCredentialRequest
        if (passkeyRequest == null) {
            fail(getString(R.string.request_invalid))
            return
        }
        val options = PublicKeyCredentialCreationOptions.fromMap(JSONObject(passkeyRequest.requestJson).toMap())
        val caller = resolveCaller(request.callingAppInfo, options.rp.id, passkeyRequest.clientDataHash) ?: return
        val rpId = options.rp.id ?: caller.effectiveDomain
        val clientData = clientData(caller, "webauthn.create", passkeyRequest.requestJson)
        val prompt = SecurityKeyPrompt(this, getString(R.string.title_create, rpId))
        // Making a passkey always wants the PIN: one made without it is turned away by browsers that
        // ask for user verification when it is used.
        when (
            val outcome =
                prompt.run(askPinFirst = true, rpId = rpId) { client, pin, state ->
                    client.makeCredential(clientData, options, caller.effectiveDomain, pin, null, state)
                }
        ) {
            is SecurityKeyPrompt.Outcome.Success -> {
                val result = Intent()
                PendingIntentHandler.setCreateCredentialResponse(result, CreatePublicKeyCredentialResponse(json(outcome.value)))
                setResult(RESULT_OK, result)
                finish()
            }

            is SecurityKeyPrompt.Outcome.Failed -> {
                fail(outcome.message, outcome.excluded)
            }

            SecurityKeyPrompt.Outcome.Cancelled -> {
                finishCancelled()
            }
        }
    }

    private suspend fun get() {
        val request = PendingIntentHandler.retrieveProviderGetCredentialRequest(intent)
        val option = request?.credentialOptions?.filterIsInstance<GetPublicKeyCredentialOption>()?.firstOrNull()
        if (option == null) {
            fail(getString(R.string.request_invalid))
            return
        }
        val options = PublicKeyCredentialRequestOptions.fromMap(JSONObject(option.requestJson).toMap())
        val caller = resolveCaller(request.callingAppInfo, options.rpId, option.clientDataHash) ?: return
        val rpId = options.rpId ?: caller.effectiveDomain
        val clientData = clientData(caller, "webauthn.get", option.requestJson)
        val prompt = SecurityKeyPrompt(this, getString(R.string.title_get, rpId))
        // Without the PIN a key will not say whose passkeys it holds, so a sign-in that leaves the
        // account to the key wants it as much as one that asks for user verification.
        val askPinFirst =
            options.userVerification != UserVerificationRequirement.DISCOURAGED || options.allowCredentials.isEmpty()
        val outcome =
            prompt.run(askPinFirst, rpId) { client, pin, state ->
                try {
                    Assertion.One(client.getAssertion(clientData, options, caller.effectiveDomain, pin, state))
                } catch (many: MultipleAssertionsAvailable) {
                    Assertion.Many(many)
                }
            }
        when (outcome) {
            is SecurityKeyPrompt.Outcome.Success -> {
                val credential =
                    when (val assertion = outcome.value) {
                        is Assertion.One -> assertion.credential
                        is Assertion.Many -> choose(assertion.assertions, rpId) ?: return finishCancelled()
                    }
                val result = Intent()
                PendingIntentHandler.setGetCredentialResponse(result, GetCredentialResponse(CredentialManagerPasskey(json(credential))))
                setResult(RESULT_OK, result)
                finish()
            }

            is SecurityKeyPrompt.Outcome.Failed -> {
                fail(outcome.message)
            }

            SecurityKeyPrompt.Outcome.Cancelled -> {
                finishCancelled()
            }
        }
    }

    private sealed interface Assertion {
        class One(
            val credential: PublicKeyCredential,
        ) : Assertion

        class Many(
            val assertions: MultipleAssertionsAvailable,
        ) : Assertion
    }

    /** Asks which of the accounts the key returned to sign in with. */
    private suspend fun choose(
        assertions: MultipleAssertionsAvailable,
        rpId: String,
    ): PublicKeyCredential? {
        // A key that was not given the PIN keeps the accounts' names to itself; the accounts are
        // still offered, by number of a kind, rather than not at all.
        val users = assertions.accounts()
        val index = AccountPicker.pick(this, users, rpId) ?: return null
        return assertions.select(index)
    }

    /**
     * Who is asking, once they have been let through: a browser the user trusts, asked about the
     * first time; or an app the website names as its own.
     */
    private suspend fun resolveCaller(
        info: CallingAppInfo,
        rpId: String?,
        clientDataHash: ByteArray?,
    ): Caller? {
        while (true) {
            try {
                return withContext(Dispatchers.IO) { Caller.resolve(this@PasskeyActivity, info, rpId, clientDataHash) }
            } catch (untrusted: Caller.UntrustedBrowser) {
                if (!askTrust(untrusted)) {
                    finishCancelled()
                    return null
                }
                TrustedBrowsers(this).trust(untrusted.packageName, untrusted.fingerprint)
            } catch (refused: Caller.Refused) {
                fail(refused.message)
                return null
            }
        }
    }

    /** A question with nothing to type, so a dialog, as the fork asks every such question. */
    private suspend fun askTrust(browser: Caller.UntrustedBrowser): Boolean = suspendCancellableCoroutine { continuation ->
        var answered = false
        val dialog =
            MaterialAlertDialogBuilder(this)
                .setTitle(getString(R.string.trust_title, browser.label))
                .setMessage(getString(R.string.trust_message, browser.label, browser.fingerprint))
                .setPositiveButton(R.string.trust_confirm) { _, _ ->
                    answered = true
                    continuation.resume(true)
                }.setNegativeButton(R.string.dialog_cancel, null)
                .setOnDismissListener { if (!answered && continuation.isActive) continuation.resume(false) }
                .show()
        continuation.invokeOnCancellation { dialog.dismiss() }
    }

    /**
     * The client data to sign. A browser has built its own and handed over its hash, which is signed
     * as it is; for an app it is built here, naming the app as the origin.
     */
    private fun clientData(
        caller: Caller,
        type: String,
        requestJson: String,
    ): ClientDataProvider {
        caller.clientDataHash?.let { return ClientDataProvider.fromHash(it) }
        val json =
            JSONObject()
                .put("type", type)
                .put("challenge", JSONObject(requestJson).getString("challenge"))
                .put("origin", caller.origin)
                .put("crossOrigin", false)
        return ClientDataProvider.fromClientDataJson(json.toString().toByteArray())
    }

    private fun json(credential: PublicKeyCredential): String = JSONObject(credential.toMap(SerializationType.JSON)).toString()

    /** Says what went wrong, then hands the failure back once it has been read. */
    private fun fail(
        message: String,
        excluded: Boolean = false,
    ) {
        if (isFinishing) return
        MaterialAlertDialogBuilder(this)
            .setTitle(R.string.error_title)
            .setMessage(message)
            .setPositiveButton(R.string.dialog_ok, null)
            .setOnDismissListener { finishWithError(message, excluded) }
            .show()
    }

    private fun finishWithError(
        message: String,
        excluded: Boolean,
    ) {
        val result = Intent()
        if (isCreate) {
            val error = if (excluded) InvalidStateError() else NotAllowedError()
            PendingIntentHandler.setCreateCredentialException(result, CreatePublicKeyCredentialDomException(error, message))
        } else {
            PendingIntentHandler.setGetCredentialException(result, GetPublicKeyCredentialDomException(NotAllowedError(), message))
        }
        setResult(RESULT_OK, result)
        finish()
    }

    private fun finishCancelled() {
        val result = Intent()
        if (isCreate) {
            PendingIntentHandler.setCreateCredentialException(result, CreateCredentialCancellationException())
        } else {
            PendingIntentHandler.setGetCredentialException(result, GetCredentialCancellationException())
        }
        setResult(RESULT_OK, result)
        finish()
    }

    companion object {
        const val ACTION_CREATE = "space.valasiadis.passkeyenabler.CREATE"
        const val ACTION_GET = "space.valasiadis.passkeyenabler.GET"
        private val logger = LoggerFactory.getLogger(PasskeyActivity::class.java)
    }
}

/** The request as the maps yubikit's WebAuthn types are read from. */
internal fun JSONObject.toMap(): Map<String, *> = keys().asSequence().associateWith { unwrap(get(it)) }

private fun unwrap(value: Any?): Any? = when (value) {
    is JSONObject -> value.toMap()
    is JSONArray -> (0 until value.length()).map { unwrap(value.get(it)) }
    JSONObject.NULL -> null
    else -> value
}
