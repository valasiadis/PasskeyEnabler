/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package space.valasiadis.passkeyenabler.ui

import androidx.appcompat.app.AppCompatActivity
import com.google.android.material.bottomsheet.BottomSheetBehavior
import com.google.android.material.bottomsheet.BottomSheetDialog
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity
import space.valasiadis.passkeyenabler.R
import space.valasiadis.passkeyenabler.databinding.PasskeyPickRowBinding
import space.valasiadis.passkeyenabler.databinding.PasskeyPickSheetBinding
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * Which of the accounts the security key holds a passkey for to sign in with: the fork's sheet of
 * rows, a heading over one block with a row per account, marked with the passkey and saying the
 * account's name and, beneath it, what else tells it apart.
 */
internal object AccountPicker {
    /** The index of the chosen account, or null when the sheet was taken down without a choice. */
    suspend fun pick(
        activity: AppCompatActivity,
        users: List<PublicKeyCredentialUserEntity?>,
        rpId: String,
    ): Int? = suspendCancellableCoroutine { continuation ->
        val sheet = BottomSheetDialog(activity)
        val content = PasskeyPickSheetBinding.inflate(activity.layoutInflater)
        content.passkeyPickHeader.sectionTitle.setText(R.string.pick_title)
        var chosen = false
        users.forEachIndexed { index, user ->
            val row = PasskeyPickRowBinding.inflate(activity.layoutInflater, content.passkeyPickRows, false)
            val (title, detail) = describe(activity, user, rpId)
            row.passkeyPickTitle.text = title
            row.passkeyPickDetail.text = detail
            row.root.setOnClickListener {
                if (chosen) return@setOnClickListener
                chosen = true
                sheet.dismiss()
                if (continuation.isActive) continuation.resume(index)
            }
            content.passkeyPickRows.addView(row.root)
        }
        sheet.setContentView(content.root)
        // Taken away without a choice is the same as cancelling.
        sheet.setOnDismissListener { if (!chosen && continuation.isActive) continuation.resume(null) }
        sheet.behavior.state = BottomSheetBehavior.STATE_EXPANDED
        sheet.behavior.skipCollapsed = true
        continuation.invokeOnCancellation { sheet.dismiss() }
        sheet.show()
    }

    /**
     * The name to show, and the line under it. Keys need not return a display name, or any name at
     * all, so an account is named by what it has: its display name, its user name, or its ID.
     */
    private fun describe(
        activity: AppCompatActivity,
        user: PublicKeyCredentialUserEntity?,
        rpId: String,
    ): Pair<String, String> {
        val displayName = user?.displayName.orEmpty()
        val name = user?.name.orEmpty()
        return when {
            displayName.isNotEmpty() && name.isNotEmpty() && name != displayName -> displayName to name
            displayName.isNotEmpty() -> displayName to rpId
            name.isNotEmpty() -> name to rpId
            user != null -> activity.getString(R.string.pick_unnamed) to activity.getString(R.string.pick_user_id, shortId(user.id))
            else -> activity.getString(R.string.pick_unnamed) to rpId
        }
    }

    private fun shortId(id: ByteArray): String = id.take(SHORT_ID_BYTES).joinToString("") { "%02x".format(it) } + if (id.size > SHORT_ID_BYTES) "…" else ""

    private const val SHORT_ID_BYTES = 6
}
