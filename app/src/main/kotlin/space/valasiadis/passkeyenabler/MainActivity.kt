/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package space.valasiadis.passkeyenabler

import android.os.Bundle
import androidx.appcompat.app.AppCompatActivity
import androidx.core.view.isVisible
import androidx.credentials.CredentialManager
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import space.valasiadis.passkeyenabler.databinding.ActivityMainBinding
import space.valasiadis.passkeyenabler.databinding.PasskeyPickRowBinding

/** Says what the app is for, opens the setting that switches it on, and lists the browsers trusted. */
class MainActivity : AppCompatActivity() {
    private lateinit var binding: ActivityMainBinding

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        binding = ActivityMainBinding.inflate(layoutInflater)
        setContentView(binding.root)
        binding.trustedHeader.sectionTitle.setText(R.string.main_trusted_header)
        binding.openSettings.setOnClickListener {
            CredentialManager.create(this).createSettingsPendingIntent().send()
        }
    }

    override fun onResume() {
        super.onResume()
        showTrusted()
    }

    private fun showTrusted() {
        val trusted = TrustedBrowsers(this)
        val browsers = trusted.all()
        binding.trustedNone.isVisible = browsers.isEmpty()
        binding.trustedRows.removeAllViews()
        for ((packageName, fingerprint) in browsers.toSortedMap()) {
            val row = PasskeyPickRowBinding.inflate(layoutInflater, binding.trustedRows, false)
            val label = Caller.label(this, packageName)
            row.passkeyPickTitle.text = label
            row.passkeyPickDetail.text = getString(R.string.main_trusted_detail, packageName, fingerprint)
            row.root.setOnClickListener {
                MaterialAlertDialogBuilder(this)
                    .setTitle(getString(R.string.main_forget_title, label))
                    .setMessage(R.string.main_forget_message)
                    .setPositiveButton(R.string.main_forget) { _, _ ->
                        trusted.forget(packageName)
                        showTrusted()
                    }.setNegativeButton(R.string.dialog_cancel, null)
                    .show()
            }
            binding.trustedRows.addView(row.root)
        }
    }
}
