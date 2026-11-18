/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package space.valasiadis.passkeyenabler

import android.app.Application
import com.google.android.material.color.DynamicColors

class PasskeyApp : Application() {
    override fun onCreate() {
        super.onCreate()
        // The wallpaper's colours, as the system's own sheets wear them.
        DynamicColors.applyToActivitiesIfAvailable(this)
    }
}
