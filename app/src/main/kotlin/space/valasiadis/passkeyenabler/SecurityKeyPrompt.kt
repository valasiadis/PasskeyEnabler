/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package space.valasiadis.passkeyenabler

import android.content.pm.PackageManager
import androidx.annotation.DrawableRes
import androidx.annotation.StringRes
import androidx.appcompat.app.AppCompatActivity
import androidx.lifecycle.DefaultLifecycleObserver
import androidx.lifecycle.LifecycleOwner
import com.yubico.yubikit.android.YubiKitManager
import com.yubico.yubikit.android.transport.nfc.NfcConfiguration
import com.yubico.yubikit.android.transport.nfc.NfcNotAvailable
import com.yubico.yubikit.android.transport.nfc.NfcYubiKeyDevice
import com.yubico.yubikit.android.transport.usb.UsbConfiguration
import com.yubico.yubikit.android.transport.usb.UsbYubiKeyDevice
import com.yubico.yubikit.core.Transport
import com.yubico.yubikit.core.YubiKeyDevice
import com.yubico.yubikit.core.application.CommandState
import com.yubico.yubikit.core.fido.CtapException
import com.yubico.yubikit.fido.client.AuthInvalidClientError
import com.yubico.yubikit.fido.client.ClientError
import com.yubico.yubikit.fido.client.Ctap2Client
import com.yubico.yubikit.fido.client.PinRequiredClientError
import com.yubico.yubikit.fido.client.WebAuthnClient
import space.valasiadis.passkeyenabler.ui.CardPrompt
import space.valasiadis.passkeyenabler.ui.PinSheet
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.async
import kotlinx.coroutines.cancel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.withTimeoutOrNull
import org.slf4j.LoggerFactory
import java.io.IOException
import java.util.concurrent.atomic.AtomicReference

/**
 * Runs one WebAuthn operation on a security key: asks for its PIN when the operation needs one,
 * waits for the key, and keeps the card prompt sheet up while the key is being worked.
 *
 * The shape is the Password Store fork's security key prompt, with yubikit doing the talking. A PIN
 * is asked for before the key is whenever it is already known one will be wanted: over NFC a key
 * cannot be held against the phone through a sheet, so asking afterwards means tapping twice. When
 * it only turns out once the key has answered, the key is let go and the PIN asked for then.
 */
internal class SecurityKeyPrompt(
    private val activity: AppCompatActivity,
    private val title: String,
) : DefaultLifecycleObserver {
    private val yubikit = YubiKitManager(activity)
    private val usbHost = activity.packageManager.hasSystemFeature(PackageManager.FEATURE_USB_HOST)
    private var nfcAvailable = false

    /** A key plugged in and allowed, for as long as it stays plugged in. */
    private val pluggedIn = AtomicReference<UsbYubiKeyDevice?>(null)

    /** Whoever is waiting for the next key to turn up. */
    private val waiting = AtomicReference<CompletableDeferred<YubiKeyDevice>?>(null)

    /**
     * Where the exchange with a key runs: a thread blocked inside it cannot be interrupted, so
     * cancelling abandons it here rather than waiting for it to notice.
     */
    private val io = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private var sheet: CardPrompt? = null
    private var cancelled: CompletableDeferred<Unit>? = null

    sealed interface Outcome<out T> {
        class Success<T>(
            val value: T,
        ) : Outcome<T>

        data object Cancelled : Outcome<Nothing>

        /** [message] is said to the user as it stands; [excluded] is the one failure with a DOM name of its own. */
        class Failed(
            val message: String,
            val error: Throwable?,
            val excluded: Boolean = false,
        ) : Outcome<Nothing>
    }

    init {
        activity.lifecycle.addObserver(this)
        yubikit.startUsbDiscovery(UsbConfiguration()) { device ->
            pluggedIn.set(device)
            device.setOnClosed { pluggedIn.compareAndSet(device, null) }
            waiting.getAndSet(null)?.complete(device)
        }
    }

    // Reader mode is only held while the screen is in front: Android takes it away otherwise.
    override fun onResume(owner: LifecycleOwner) {
        nfcAvailable =
            try {
                yubikit.startNfcDiscovery(NfcConfiguration().timeout(NFC_TIMEOUT_MS), activity) { device ->
                    waiting.getAndSet(null)?.complete(device)
                }
                true
            } catch (_: NfcNotAvailable) {
                false
            }
    }

    override fun onPause(owner: LifecycleOwner) {
        yubikit.stopNfcDiscovery(activity)
    }

    override fun onDestroy(owner: LifecycleOwner) {
        yubikit.stopUsbDiscovery()
        sheet?.dismiss()
        io.cancel()
    }

    /**
     * Runs [operation] on the first security key to turn up, as often as it takes: again after a
     * wrong PIN, again after a key lifted too soon.
     */
    suspend fun <T> run(
        askPinFirst: Boolean,
        rpId: String,
        operation: (WebAuthnClient, CharArray?, CommandState) -> T,
    ): Outcome<T> {
        if (!nfcAvailable && !usbHost) return failed(R.string.security_key_reader_unavailable)
        var pin: CharArray? = null
        var needPin = askPinFirst
        var pinError: String? = null
        var message = presentMessage()
        var transportFailures = 0
        try {
            while (true) {
                if (needPin) {
                    dismissSheet()
                    val entry = PinSheet.ask(activity, title, pinError) ?: return Outcome.Cancelled
                    pin?.fill('\u0000')
                    pin = entry
                    needPin = false
                    pinError = null
                    message = presentMessage()
                }
                val attempt = attempt(message, pin, operation)
                val device = attempt.device
                when (attempt) {
                    is Attempt.Success -> {
                        showDone()
                        releaseWhenLifted(attempt.device)
                        return Outcome.Success(attempt.value)
                    }

                    is Attempt.Cancelled -> {
                        return Outcome.Cancelled
                    }

                    is Attempt.Error -> {
                        val error = attempt.error
                        val ctapError = (error.cause as? CtapException)?.ctapError ?: (error as? CtapException)?.ctapError
                        when {
                            error is PinRequiredClientError -> {
                                needPin = true
                            }

                            error is AuthInvalidClientError && error.authType == AuthInvalidClientError.AuthType.PIN -> {
                                if (error.retries == 0) return failed(R.string.security_key_pin_blocked, error)
                                pinError = wrongPinMessage(error.retries)
                                needPin = true
                            }

                            // The fingerprint was not recognised: say so and take the PIN instead.
                            error is AuthInvalidClientError || ctapError == CtapException.ERR_UV_BLOCKED ||
                                ctapError == CtapException.ERR_PUAT_REQUIRED -> {
                                pinError = activity.getString(R.string.security_key_uv_blocked)
                                needPin = true
                            }

                            error is IOException && error !is CtapException &&
                                ++transportFailures <= MAX_TRANSPORT_RETRIES -> {
                                message = retryMessage(device?.transport)
                            }

                            else -> {
                                logger.warn("Security key operation failed", error)
                                return failure(error, ctapError, device?.transport, rpId)
                            }
                        }
                        // Going round again: let this key go before waiting for the next one.
                        if (device is NfcYubiKeyDevice) awaitRemoval(device, RETRY_REMOVAL_MS)
                    }
                }
            }
        } finally {
            pin?.fill('\u0000')
            dismissSheet()
        }
    }

    private sealed interface Attempt<out T> {
        val device: YubiKeyDevice?

        class Success<T>(
            val value: T,
            override val device: YubiKeyDevice,
        ) : Attempt<T>

        class Cancelled(
            override val device: YubiKeyDevice?,
        ) : Attempt<Nothing>

        class Error(
            val error: Throwable,
            override val device: YubiKeyDevice?,
        ) : Attempt<Nothing>
    }

    /**
     * Waits for a key and runs [operation] on it. The exchange blocks a thread and may be waiting for
     * a finger; cancelling tells the key to stop where it can (over USB) and otherwise abandons it.
     */
    private suspend fun <T> attempt(
        message: String,
        pin: CharArray?,
        operation: (WebAuthnClient, CharArray?, CommandState) -> T,
    ): Attempt<T> = coroutineScope {
        val cancel = CompletableDeferred<Unit>()
        cancelled = cancel
        showAsking(message)
        val state =
            object : CommandState() {
                override fun onKeepAliveStatus(status: Byte) {
                    if (status == CommandState.STATUS_UPNEEDED) activity.runOnUiThread { announceTouch() }
                }
            }
        val device = async { awaitDevice() }
        val picked =
            select {
                device.onAwait { it }
                cancel.onAwait { null }
            }
        if (picked == null) {
            device.cancel()
            return@coroutineScope Attempt.Cancelled(null)
        }
        announceWorking(picked.transport)
        val work =
            io.async {
                try {
                    WebAuthnClient.create(picked, null).use { client ->
                        checkReady(client)
                        Attempt.Success(operation(client, pin, state), picked)
                    }
                } catch (e: CancellationException) {
                    throw e
                } catch (e: Throwable) {
                    Attempt.Error(e, picked)
                }
            }
        select<Attempt<T>> {
            work.onAwait { it }
            cancel.onAwait {
                state.cancel()
                work.cancel()
                Attempt.Cancelled(picked)
            }
        }
    }

    /** Turns away a key that cannot be used as it is, before it is asked for anything. */
    private fun checkReady(client: WebAuthnClient) {
        val ctap2 = client as? Ctap2Client ?: return
        if (ctap2.session.cachedInfo.forcePinChange) {
            throw ClientError(ClientError.Code.BAD_REQUEST, CtapException(CtapException.ERR_PIN_POLICY_VIOLATION))
        }
    }

    private suspend fun awaitDevice(): YubiKeyDevice {
        pluggedIn.get()?.let { return it }
        val next = CompletableDeferred<YubiKeyDevice>()
        waiting.set(next)
        // A key plugged in between the look above and now has nobody waiting for it yet.
        pluggedIn.get()?.let { if (waiting.compareAndSet(next, null)) return it }
        return try {
            next.await()
        } finally {
            waiting.compareAndSet(next, null)
        }
    }

    private fun showAsking(message: String) {
        val state =
            CardPrompt.State(
                mark = presentMark(),
                title = title,
                message = message,
                working = false,
                cropped = !(usbHost && !nfcAvailable),
            )
        val shown = sheet
        if (shown != null && shown.isShowing) {
            shown.show(state)
        } else {
            sheet = CardPrompt.show(activity, state) { cancelled?.complete(Unit) }
        }
    }

    private fun announceWorking(transport: Transport) {
        sheet?.show(
            CardPrompt.State(
                mark = mark(transport),
                title = activity.getString(R.string.security_key_hold_title),
                message =
                activity.getString(
                    if (transport == Transport.USB) R.string.security_key_hold_usb else R.string.security_key_hold,
                ),
                working = true,
                cropped = transport == Transport.NFC,
            ),
        )
    }

    private fun announceTouch() {
        sheet?.show(
            CardPrompt.State(
                mark = R.drawable.ic_touch_app_24dp,
                title = activity.getString(R.string.security_key_touch_title),
                message = "",
                working = true,
                framed = false,
            ),
        )
    }

    private fun showDone() {
        sheet?.show(CardPrompt.done(activity, R.string.security_key_done_title))
    }

    private fun dismissSheet() {
        sheet?.dismiss()
        sheet = null
    }

    /**
     * Lets the tick be read, then lets the key go. Over NFC the reader is held until the key has been
     * lifted, so the phone does not open the key's own NDEF link the moment this screen goes.
     */
    private suspend fun releaseWhenLifted(device: YubiKeyDevice) {
        if (device is NfcYubiKeyDevice) {
            delay(MIN_DONE_MS)
            awaitRemoval(device, READER_HOLD_MS)
        } else {
            delay(CardPrompt.SUCCESS_MS)
        }
    }

    private suspend fun awaitRemoval(
        device: NfcYubiKeyDevice,
        timeoutMs: Long,
    ) {
        val removed = CompletableDeferred<Unit>()
        device.remove { removed.complete(Unit) }
        withTimeoutOrNull(timeoutMs) { removed.await() }
    }

    @DrawableRes
    private fun presentMark(): Int = if (usbHost && !nfcAvailable) R.drawable.ic_usb_24dp else R.drawable.ic_contactless_24dp

    @DrawableRes
    private fun mark(transport: Transport): Int = if (transport == Transport.USB) R.drawable.ic_usb_24dp else R.drawable.ic_contactless_24dp

    private fun presentMessage(): String = activity.getString(
        when {
            nfcAvailable && usbHost -> R.string.security_key_present_any
            usbHost -> R.string.security_key_present_usb
            else -> R.string.security_key_present
        },
    )

    private fun retryMessage(transport: Transport?): String = activity.getString(
        when (transport) {
            Transport.NFC -> R.string.security_key_comm_failed
            Transport.USB -> R.string.security_key_comm_failed_usb
            null -> R.string.security_key_comm_failed_any
        },
    )

    private fun wrongPinMessage(retries: Int): String = if (retries > 0) {
        activity.resources.getQuantityString(R.plurals.security_key_wrong_pin_remaining, retries, retries)
    } else {
        activity.getString(R.string.security_key_wrong_pin)
    }

    private fun failed(
        @StringRes message: Int,
        error: Throwable? = null,
    ): Outcome.Failed = Outcome.Failed(activity.getString(message), error)

    /** What to tell the user about a failure that was not a wrong PIN. */
    private fun failure(
        error: Throwable,
        ctapError: Byte?,
        transport: Transport?,
        rpId: String,
    ): Outcome.Failed = when (ctapError) {
        CtapException.ERR_PIN_BLOCKED -> {
            failed(R.string.security_key_pin_blocked, error)
        }

        CtapException.ERR_PIN_AUTH_BLOCKED -> {
            failed(
                if (transport == Transport.NFC) R.string.security_key_reinsert_nfc else R.string.security_key_reinsert,
                error,
            )
        }

        CtapException.ERR_PIN_NOT_SET -> {
            failed(R.string.security_key_no_pin, error)
        }

        CtapException.ERR_PIN_POLICY_VIOLATION -> {
            failed(R.string.security_key_pin_change, error)
        }

        CtapException.ERR_NO_CREDENTIALS -> {
            Outcome.Failed(activity.getString(R.string.security_key_no_credentials, rpId), error)
        }

        CtapException.ERR_CREDENTIAL_EXCLUDED -> {
            Outcome.Failed(activity.getString(R.string.security_key_excluded, rpId), error, excluded = true)
        }

        CtapException.ERR_KEY_STORE_FULL -> {
            failed(R.string.security_key_full, error)
        }

        CtapException.ERR_UNSUPPORTED_ALGORITHM,
        CtapException.ERR_UNSUPPORTED_OPTION,
        CtapException.ERR_UNSUPPORTED_EXTENSION,
        -> {
            Outcome.Failed(activity.getString(R.string.security_key_unsupported, rpId), error)
        }

        CtapException.ERR_USER_ACTION_TIMEOUT,
        CtapException.ERR_ACTION_TIMEOUT,
        -> {
            failed(R.string.security_key_touch_timeout, error)
        }

        CtapException.ERR_OPERATION_DENIED,
        CtapException.ERR_NOT_ALLOWED,
        CtapException.ERR_KEEPALIVE_CANCEL,
        -> {
            failed(R.string.security_key_denied, error)
        }

        null -> {
            // No PIN set on a key that needs one to verify the user comes without a CTAP status.
            if (error is ClientError && error.errorCode == ClientError.Code.CONFIGURATION_UNSUPPORTED) {
                failed(R.string.security_key_no_pin, error)
            } else {
                Outcome.Failed(error.message ?: activity.getString(R.string.error_title), error)
            }
        }

        else -> {
            Outcome.Failed(
                activity.getString(R.string.security_key_error_generic, "0x%02x".format(ctapError)),
                error,
            )
        }
    }

    companion object {
        private val logger = LoggerFactory.getLogger(SecurityKeyPrompt::class.java)
        private const val NFC_TIMEOUT_MS = 5_000
        private const val MAX_TRANSPORT_RETRIES = 8
        private const val MIN_DONE_MS = 600L
        private const val READER_HOLD_MS = 4_000L
        private const val RETRY_REMOVAL_MS = 1_500L
    }
}
