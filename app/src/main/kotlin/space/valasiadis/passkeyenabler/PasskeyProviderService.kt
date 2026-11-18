/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package space.valasiadis.passkeyenabler

import android.app.PendingIntent
import android.content.Intent
import android.graphics.drawable.Icon
import android.os.CancellationSignal
import android.os.OutcomeReceiver
import androidx.credentials.exceptions.ClearCredentialException
import androidx.credentials.exceptions.CreateCredentialException
import androidx.credentials.exceptions.CreateCredentialUnknownException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.provider.BeginCreateCredentialRequest
import androidx.credentials.provider.BeginCreateCredentialResponse
import androidx.credentials.provider.BeginCreatePublicKeyCredentialRequest
import androidx.credentials.provider.BeginGetCredentialRequest
import androidx.credentials.provider.BeginGetCredentialResponse
import androidx.credentials.provider.BeginGetPublicKeyCredentialOption
import androidx.credentials.provider.CreateEntry
import androidx.credentials.provider.CredentialEntry
import androidx.credentials.provider.CredentialProviderService
import androidx.credentials.provider.ProviderClearCredentialStateRequest
import androidx.credentials.provider.PublicKeyCredentialEntry
import java.util.concurrent.atomic.AtomicInteger

/**
 * Offers the security key to the system's passkey sheet.
 *
 * Nothing is known of what the key holds until it is presented, so for every passkey request this
 * offers one entry, "Security key", and leaves the rest to [PasskeyActivity], which the entry opens.
 */
class PasskeyProviderService : CredentialProviderService() {
    override fun onBeginCreateCredentialRequest(
        request: BeginCreateCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginCreateCredentialResponse, CreateCredentialException>,
    ) {
        if (request !is BeginCreatePublicKeyCredentialRequest) {
            callback.onError(CreateCredentialUnknownException("Only passkeys are supported"))
            return
        }
        val entry =
            CreateEntry
                .Builder(getString(R.string.entry_account), pendingIntent(PasskeyActivity.ACTION_CREATE))
                .setDescription(getString(R.string.entry_create_detail))
                .setIcon(Icon.createWithResource(this, R.drawable.ic_security_key_24dp))
                .build()
        callback.onResult(BeginCreateCredentialResponse.Builder().addCreateEntry(entry).build())
    }

    override fun onBeginGetCredentialRequest(
        request: BeginGetCredentialRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<BeginGetCredentialResponse, GetCredentialException>,
    ) {
        val entries =
            request.beginGetCredentialOptions.filterIsInstance<BeginGetPublicKeyCredentialOption>().map { option ->
                PublicKeyCredentialEntry
                    .Builder(this, getString(R.string.entry_account), pendingIntent(PasskeyActivity.ACTION_GET), option)
                    .setDisplayName(getString(R.string.entry_get_detail))
                    .setIcon(Icon.createWithResource(this, R.drawable.ic_security_key_24dp))
                    .build()
            }
        callback.onResult(BeginGetCredentialResponse.Builder().setCredentialEntries(entries.map<PublicKeyCredentialEntry, CredentialEntry> { it }).build())
    }

    override fun onClearCredentialStateRequest(
        request: ProviderClearCredentialStateRequest,
        cancellationSignal: CancellationSignal,
        callback: OutcomeReceiver<Void?, ClearCredentialException>,
    ) {
        // Nothing is kept about who signed in where.
        callback.onResult(null)
    }

    /**
     * An intent the system fills in with the request once the entry is picked. Each gets a request
     * code of its own, so that two entries are never folded into one.
     */
    private fun pendingIntent(action: String): PendingIntent = PendingIntent.getActivity(
        this,
        requestCodes.incrementAndGet(),
        Intent(this, PasskeyActivity::class.java).setAction(action),
        PendingIntent.FLAG_MUTABLE or PendingIntent.FLAG_UPDATE_CURRENT,
    )

    private companion object {
        val requestCodes = AtomicInteger()
    }
}
