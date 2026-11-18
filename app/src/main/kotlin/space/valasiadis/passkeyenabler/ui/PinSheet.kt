/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package space.valasiadis.passkeyenabler.ui

import android.view.WindowManager
import android.view.inputmethod.EditorInfo
import androidx.appcompat.app.AppCompatActivity
import androidx.core.widget.doAfterTextChanged
import space.valasiadis.passkeyenabler.R
import space.valasiadis.passkeyenabler.databinding.SheetPinEntryBinding
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred

/**
 * Asks for the security key's PIN from the fork's input sheet: the PIN as a field in a block of its
 * own, the way out quiet on the left and the action filled on the right.
 */
internal object PinSheet {
    /** CTAP2's least PIN length, below which the key will not even look at what was typed. */
    private const val MIN_LENGTH = 4

    /**
     * The PIN, or null when the sheet was taken down without one. [reason] says what the PIN is for,
     * and [error] what went wrong with the last one.
     */
    suspend fun ask(
        activity: AppCompatActivity,
        reason: String,
        error: String?,
    ): CharArray? {
        if (activity.isFinishing || activity.isDestroyed) return null
        val result = CompletableDeferred<CharArray?>()
        val binding = SheetPinEntryBinding.inflate(activity.layoutInflater)
        val sheet =
            InputSheet.create(
                context = activity,
                title = activity.getString(R.string.security_key_pin_title),
                content = binding.root,
                primaryLabel = activity.getString(R.string.dialog_ok),
                message = reason,
            ) {
                val text = binding.pinEditText.text
                val pin = text?.let { CharArray(it.length) { index -> it[index] } } ?: charArrayOf()
                text?.clear()
                result.complete(pin)
            }
        val dialog = sheet.dialog
        // Each way of leaving answers the question exactly once: the PIN, or nothing.
        dialog.setOnCancelListener { result.complete(null) }
        dialog.setOnDismissListener { result.complete(null) }
        // The error takes the caption under the field when there is one; the least length otherwise.
        if (error != null) {
            binding.pinField.error = error
        } else {
            binding.pinField.helperText =
                activity.resources.getQuantityString(R.plurals.pin_min_length, MIN_LENGTH, MIN_LENGTH)
        }
        val ok = sheet.primary
        val enough = { (binding.pinEditText.text?.length ?: 0) >= MIN_LENGTH }
        ok.isEnabled = enough()
        binding.pinEditText.doAfterTextChanged { ok.isEnabled = enough() }
        binding.pinEditText.setOnEditorActionListener { _, action, _ ->
            if (action == EditorInfo.IME_ACTION_DONE && enough()) ok.performClick()
            action == EditorInfo.IME_ACTION_DONE
        }
        dialog.window?.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        dialog.show()
        return try {
            result.await()
        } catch (e: CancellationException) {
            dialog.dismiss()
            throw e
        }
    }
}
