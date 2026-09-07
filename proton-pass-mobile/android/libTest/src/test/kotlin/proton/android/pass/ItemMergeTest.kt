/*
 *  Copyright (c) 2026 Proton AG
 *  This file is part of Proton AG and Proton Pass.
 *
 *  Proton Pass is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Proton Pass is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Proton Pass.  If not, see <https://www.gnu.org/licenses/>.
 *
 */

package proton.android.pass

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import proton.android.pass.common.MergeFieldKind
import proton.android.pass.common.MergeActionKind
import proton.android.pass.common.ItemForMerge
import proton.android.pass.commonrust.ItemMerger
import proton.android.pass.types.CardType
import proton.android.pass.types.CreditCardItem
import proton.android.pass.types.CustomSection
import proton.android.pass.types.ItemContent
import proton.android.pass.types.ItemData
import proton.android.pass.types.ItemExtraField
import proton.android.pass.types.ItemExtraFieldContent
import proton.android.pass.types.LoginItem
import proton.android.pass.types.NoteItem
import proton.android.pass.types.Passkey
import proton.android.pass.types.WifiItem
import proton.android.pass.types.WifiSecurity

class ItemMergeTest {

    private val merger = ItemMerger()

    private fun passkey(keyId: String) = Passkey(
        keyId = keyId,
        content = byteArrayOf(),
        domain = "example.com",
        rpId = "example.com",
        rpName = "",
        userName = "",
        userDisplayName = "",
        userId = byteArrayOf(),
        createTime = 0u,
        note = "",
        credentialId = byteArrayOf(),
        userHandle = byteArrayOf(),
        creationData = null,
    )

    private fun loginForMerge(
        itemId: String,
        title: String,
        username: String = "",
        password: String = "",
        totpUri: String = "",
        urls: List<String> = emptyList(),
        passkeys: List<Passkey> = emptyList(),
        extraFields: List<ItemExtraField> = emptyList(),
    ) = ItemForMerge(
        itemId = itemId,
        shareId = "share",
        item = ItemData(
            title = title,
            note = "",
            itemUuid = "$itemId-uuid",
            content = ItemContent.Login(
                LoginItem(
                    email = "",
                    username = username,
                    password = password,
                    urls = urls,
                    totpUri = totpUri,
                    passkeys = passkeys,
                    autofillUrls = emptyList(),
                ),
            ),
            extraFields = extraFields,
            platformSpecific = null,
            customIcon = null,
        ),
    )

    private fun noteForMerge(itemId: String, title: String, note: String) = ItemForMerge(
        itemId = itemId,
        shareId = "share",
        item = ItemData(
            title = title,
            note = note,
            itemUuid = "$itemId-uuid",
            content = ItemContent.Note(NoteItem()),
            extraFields = emptyList(),
            platformSpecific = null,
            customIcon = null,
        ),
    )

    private fun customForMerge(itemId: String, title: String, fieldName: String, fieldValue: String) = ItemForMerge(
        itemId = itemId,
        shareId = "share",
        item = ItemData(
            title = title,
            note = "",
            itemUuid = "$itemId-uuid",
            content = ItemContent.Custom(
                proton.android.pass.types.CustomItem(
                    sections = listOf(
                        CustomSection(
                            sectionName = "section",
                            sectionFields = listOf(
                                ItemExtraField(fieldName, ItemExtraFieldContent.Text(fieldValue)),
                            ),
                        ),
                    ),
                ),
            ),
            extraFields = emptyList(),
            platformSpecific = null,
            customIcon = null,
        ),
    )

    private fun loginOf(item: ItemData): LoginItem {
        val content = item.content
        assertThat(content).isInstanceOf(ItemContent.Login::class.java)
        return (content as ItemContent.Login).v1
    }

    private fun actionOf(
        plan: proton.android.pass.common.MergePlan,
        field: MergeFieldKind,
    ): MergeActionKind = plan.actions.first { it.field == field }.kind

    @Test
    fun `titles differ keeps primary title`() {
        val primary = loginForMerge("1", title = "Amazon", username = "bob", password = "pw")
        val secondary = loginForMerge("2", title = "Amazon (old)", username = "bob", password = "pw")

        val plan = merger.planMerge(primary, secondary)

        assertThat(plan.mergedItem.title).isEqualTo("Amazon")
        assertThat(actionOf(plan, MergeFieldKind.TITLE)).isEqualTo(MergeActionKind.KEEP_PRIMARY)
    }

    @Test
    fun `different totp secret is preserved as totp custom field`() {
        val primary = loginForMerge("1", title = "Amazon", username = "bob", password = "pw", totpUri = "otpauth://totp/primary")
        val secondary = loginForMerge("2", title = "Amazon", username = "bob", password = "pw", totpUri = "otpauth://totp/secondary")

        val plan = merger.planMerge(primary, secondary)

        val login = loginOf(plan.mergedItem)
        assertThat(login.totpUri).isEqualTo("otpauth://totp/primary")
        assertThat(plan.mergedItem.extraFields).containsExactly(
            ItemExtraField("Amazon - TOTP", ItemExtraFieldContent.Totp("otpauth://totp/secondary")),
        )
        assertThat(actionOf(plan, MergeFieldKind.TOTP)).isEqualTo(MergeActionKind.CONFLICT_TO_CUSTOM_FIELD)
    }

    @Test
    fun `empty primary totp is filled from secondary`() {
        val primary = loginForMerge("1", title = "Amazon", username = "bob", password = "pw")
        val secondary = loginForMerge("2", title = "Amazon", username = "bob", password = "pw", totpUri = "otpauth://totp/secondary")

        val plan = merger.planMerge(primary, secondary)

        assertThat(loginOf(plan.mergedItem).totpUri).isEqualTo("otpauth://totp/secondary")
        assertThat(plan.mergedItem.extraFields).isEmpty()
        assertThat(actionOf(plan, MergeFieldKind.TOTP)).isEqualTo(MergeActionKind.TAKE_SECONDARY)
    }

    @Test
    fun `urls are unioned primary first with exact duplicates removed`() {
        val primary = loginForMerge(
            "1",
            title = "Amazon",
            username = "bob",
            password = "pw",
            urls = listOf("https://amazon.com", "https://shop.com"),
        )
        val secondary = loginForMerge(
            "2",
            title = "Amazon",
            username = "bob",
            password = "pw",
            urls = listOf("https://amazon.com", "https://smile.amazon.com"),
        )

        val plan = merger.planMerge(primary, secondary)

        assertThat(loginOf(plan.mergedItem).urls).containsExactly(
            "https://amazon.com",
            "https://shop.com",
            "https://smile.amazon.com",
        ).inOrder()
        assertThat(loginOf(plan.mergedItem).autofillUrls.map { it.url }).containsExactly(
            "https://amazon.com",
            "https://shop.com",
            "https://smile.amazon.com",
        ).inOrder()
        assertThat(actionOf(plan, MergeFieldKind.AUTOFILL_URLS)).isEqualTo(MergeActionKind.UNION)
    }

    @Test
    fun `passkeys are unioned by key id`() {
        val primary = loginForMerge("1", title = "Amazon", username = "bob", password = "pw", passkeys = listOf(passkey("k1"), passkey("k2")))
        val secondary = loginForMerge("2", title = "Amazon", username = "bob", password = "pw", passkeys = listOf(passkey("k2"), passkey("k3")))

        val plan = merger.planMerge(primary, secondary)

        assertThat(loginOf(plan.mergedItem).passkeys.map { it.keyId }).containsExactly("k1", "k2", "k3").inOrder()
    }


    @Test
    fun `extra fields same name different value keeps both with source title`() {
        val primary = noteForMerge("1", title = "Amazon", note = "")
            .let {
                it.copy(item = it.item.copy(extraFields = listOf(ItemExtraField("Router", ItemExtraFieldContent.Text("1.2.3.4")))))
            }
        val secondary = noteForMerge("2", title = "Amazon", note = "")
            .let {
                it.copy(item = it.item.copy(extraFields = listOf(ItemExtraField("Router", ItemExtraFieldContent.Text("5.6.7.8")))))
            }

        val plan = merger.planMerge(primary, secondary)

        assertThat(plan.mergedItem.extraFields).containsExactly(
            ItemExtraField("Router", ItemExtraFieldContent.Text("1.2.3.4")),
            ItemExtraField("Amazon - Router", ItemExtraFieldContent.Text("5.6.7.8")),
        ).inOrder()
    }

    @Test
    fun `conflicting note is preserved as custom field`() {
        val primary = noteForMerge("1", title = "Amazon", note = "primary note")
        val secondary = noteForMerge("2", title = "Amazon", note = "secondary note")

        val plan = merger.planMerge(primary, secondary)

        assertThat(plan.mergedItem.note).isEqualTo("primary note")
        assertThat(plan.mergedItem.extraFields).containsExactly(
            ItemExtraField("Amazon - Note", ItemExtraFieldContent.Text("secondary note")),
        )
    }

    @Test
    fun `custom item sections are unioned by name with conflicting fields source named`() {
        val primary = customForMerge("1", title = "Main card", fieldName = "Number", fieldValue = "1111")
        val secondary = customForMerge("2", title = "Old card", fieldName = "Number", fieldValue = "2222")

        val plan = merger.planMerge(primary, secondary)

        val content = plan.mergedItem.content as ItemContent.Custom
        assertThat(content.v1.sections).hasSize(1)
        assertThat(content.v1.sections[0].sectionFields).containsExactly(
            ItemExtraField("Number", ItemExtraFieldContent.Text("1111")),
            ItemExtraField("Old card - section.Number", ItemExtraFieldContent.Text("2222")),
        ).inOrder()
        assertThat(actionOf(plan, MergeFieldKind.SECTION)).isEqualTo(MergeActionKind.UNION)
    }

    @Test
    fun `credit card fields are merged individually`() {
        val cardForMerge = fun(itemId: String, title: String, number: String, pin: String) = ItemForMerge(
            itemId = itemId,
            shareId = "share",
            item = ItemData(
                title = title,
                note = "",
                itemUuid = "$itemId-uuid",
                content = ItemContent.CreditCard(
                    CreditCardItem(
                        cardholderName = "Bob",
                        cardType = CardType.VISA,
                        number = number,
                        verificationNumber = "123",
                        expirationDate = "12/28",
                        pin = pin,
                    ),
                ),
                extraFields = emptyList(),
                platformSpecific = null,
                customIcon = null,
            ),
        )
        val primary = cardForMerge("1", "Main card", "4242", "1234")
        val secondary = cardForMerge("2", "Old card", "1111", "9999")

        val plan = merger.planMerge(primary, secondary)

        val card = (plan.mergedItem.content as ItemContent.CreditCard).v1
        assertThat(card.number).isEqualTo("4242")
        assertThat(card.pin).isEqualTo("1234")
        assertThat(plan.mergedItem.extraFields).containsExactly(
            ItemExtraField("Old card - Number", ItemExtraFieldContent.Hidden("1111")),
            ItemExtraField("Old card - PIN", ItemExtraFieldContent.Hidden("9999")),
        ).inOrder()
        assertThat(actionOf(plan, MergeFieldKind.CARD_NUMBER)).isEqualTo(MergeActionKind.CONFLICT_TO_CUSTOM_FIELD)
    }

    @Test
    fun `wifi fields are merged individually`() {
        val wifiForMerge = fun(itemId: String, title: String, ssid: String, password: String, security: WifiSecurity) =
            ItemForMerge(
                itemId = itemId,
                shareId = "share",
                item = ItemData(
                    title = title,
                    note = "",
                    itemUuid = "$itemId-uuid",
                    content = ItemContent.Wifi(
                        WifiItem(
                            ssid = ssid,
                            password = password,
                            security = security,
                            sections = emptyList(),
                        ),
                    ),
                    extraFields = emptyList(),
                    platformSpecific = null,
                    customIcon = null,
                ),
            )
        val primary = wifiForMerge("1", "Home", "MyWifi", "pw1", WifiSecurity.WPA2)
        val secondary = wifiForMerge("2", "Home 2", "MyWifi", "pw2", WifiSecurity.WPA3)

        val plan = merger.planMerge(primary, secondary)

        val wifi = (plan.mergedItem.content as ItemContent.Wifi).v1
        assertThat(wifi.ssid).isEqualTo("MyWifi")
        assertThat(wifi.password).isEqualTo("pw1")
        assertThat(wifi.security).isEqualTo(WifiSecurity.WPA2)
        assertThat(plan.mergedItem.extraFields).containsExactly(
            ItemExtraField("Home 2 - Password", ItemExtraFieldContent.Hidden("pw2")),
            ItemExtraField("Home 2 - Security", ItemExtraFieldContent.Hidden("WPA3")),
        ).inOrder()
        assertThat(actionOf(plan, MergeFieldKind.WIFI_PASSWORD)).isEqualTo(MergeActionKind.CONFLICT_TO_CUSTOM_FIELD)
    }

    @Test
    fun `different item types are rejected`() {
        val primary = loginForMerge("1", title = "Amazon", username = "bob", password = "pw")
        val secondary = noteForMerge("2", title = "Amazon", note = "")

        val exception = runCatching { merger.planMerge(primary, secondary) }.exceptionOrNull()

        assertThat(exception).isNotNull()
        assertThat(exception!!.message).contains("Cannot merge")
    }

    @Test
    fun `three item group folds in visual order`() {
        val primary = loginForMerge(
            "1",
            title = "Amazon",
            username = "bob",
            password = "pw",
            totpUri = "otpauth://totp/primary",
            urls = listOf("https://amazon.com"),
        )
        val secondary1 = loginForMerge(
            "2",
            title = "Amazon 2",
            username = "bobby",
            password = "pw2",
            totpUri = "otpauth://totp/secondary-1",
            urls = listOf("https://smile.amazon.com"),
        )
        val secondary2 = loginForMerge(
            "3",
            title = "Amazon 3",
            username = "bobbie",
            password = "pw3",
            totpUri = "otpauth://totp/secondary-2",
            urls = listOf("https://shop.com"),
        )

        val group = merger.planGroupMerge(primary, listOf(secondary1, secondary2))

        assertThat(group.secondaryPlans).hasSize(2)
        val login = loginOf(group.mergedItem)
        assertThat(login.urls).containsExactly(
            "https://amazon.com",
            "https://smile.amazon.com",
            "https://shop.com",
        ).inOrder()
        assertThat(login.autofillUrls.map { it.url }).containsExactly(
            "https://amazon.com",
            "https://smile.amazon.com",
            "https://shop.com",
        ).inOrder()
        assertThat(login.totpUri).isEqualTo("otpauth://totp/primary")
        assertThat(group.mergedItem.extraFields.map { it.name }).containsExactly(
            "Amazon 2 - Username",
            "Amazon 2 - Password",
            "Amazon 2 - TOTP",
            "Amazon 3 - Username",
            "Amazon 3 - Password",
            "Amazon 3 - TOTP",
        ).inOrder()
    }

    @Test
    fun `identical items produce an unchanged merge`() {
        val primary = loginForMerge(
            "1",
            title = "Amazon",
            username = "bob",
            password = "pw",
            totpUri = "otpauth://totp/x",
            urls = listOf("https://amazon.com"),
            passkeys = listOf(passkey("k1")),
        )
        val secondary = loginForMerge(
            "2",
            title = "Amazon",
            username = "bob",
            password = "pw",
            totpUri = "otpauth://totp/x",
            urls = listOf("https://amazon.com"),
            passkeys = listOf(passkey("k1")),
        )

        val plan = merger.planMerge(primary, secondary)

        assertThat(plan.mergedItem.title).isEqualTo("Amazon")
        assertThat(plan.mergedItem.extraFields).isEmpty()
        assertThat(plan.actions.map { it.kind }).doesNotContain(MergeActionKind.CONFLICT_TO_CUSTOM_FIELD)
    }
}
