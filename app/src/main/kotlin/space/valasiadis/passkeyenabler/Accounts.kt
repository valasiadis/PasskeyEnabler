/*
 * Copyright © 2014-2026 The Android Password Store Authors. All Rights Reserved.
 * SPDX-License-Identifier: GPL-3.0-only
 */

package space.valasiadis.passkeyenabler

import com.yubico.yubikit.core.util.Pair
import com.yubico.yubikit.fido.client.MultipleAssertionsAvailable
import com.yubico.yubikit.fido.ctap.Ctap2Session
import com.yubico.yubikit.fido.webauthn.PublicKeyCredentialUserEntity
import org.slf4j.LoggerFactory

private val logger = LoggerFactory.getLogger("Accounts")

/**
 * The accounts a key returned passkeys for, in the order [MultipleAssertionsAvailable.select] takes
 * them; null for an account the key said nothing about.
 *
 * yubikit up to 3.3.0 insists on a name and a display name for each, which CTAP does not promise
 * and many keys leave out, and fails on the whole list when one is missing. Until a release takes
 * the fix (https://github.com/Yubico/yubikit-android/pull/410), the key's
 * answers are read here and taken as that fix takes them: only the ID is needed, a missing name is
 * empty, and a missing display name falls back to the name.
 */
internal fun MultipleAssertionsAvailable.accounts(): List<PublicKeyCredentialUserEntity?> {
    runCatching { return users }.onFailure { logger.info("yubikit could not list the accounts: {}", it.toString()) }
    return runCatching {
        val field = MultipleAssertionsAvailable::class.java.getDeclaredField("assertions")
        field.isAccessible = true
        (field.get(this) as List<*>).map { pair ->
            val assertion = (pair as Pair<*, *>).first as Ctap2Session.AssertionData
            assertion.user?.let(::userFromKey)
        }
    }.onFailure { logger.warn("Could not read the accounts the key returned", it) }
        .getOrElse { List(assertionCount) { null } }
}

private fun userFromKey(user: Map<String, *>): PublicKeyCredentialUserEntity? {
    val id = user[PublicKeyCredentialUserEntity.ID] as? ByteArray ?: return null
    val name = user[PublicKeyCredentialUserEntity.NAME] as? String ?: ""
    val displayName = (user[PublicKeyCredentialUserEntity.DISPLAY_NAME] as? String)?.takeIf { it.isNotEmpty() } ?: name
    return PublicKeyCredentialUserEntity(name, id, displayName)
}
