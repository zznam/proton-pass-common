package proton.android.pass

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import proton.android.pass.commonrust.CxfSerialization
import proton.android.pass.common.CxfExportInput
import proton.android.pass.common.CxfVaultWithItems
import proton.android.pass.common.ItemMetadata
import proton.android.pass.common.ItemWithMetadata
import proton.android.pass.types.ItemContent
import proton.android.pass.types.ItemData
import proton.android.pass.types.LoginItem
import proton.android.pass.types.VaultColor
import proton.android.pass.types.VaultData
import proton.android.pass.types.VaultDisplayPreferences
import proton.android.pass.types.VaultIcon

class CxfTest {

    private val cxf = CxfSerialization()

    private fun loginItem(title: String, email: String, password: String, username: String = "") = ItemData(
        title = title,
        note = "",
        itemUuid = "test-uuid-login",
        content = ItemContent.Login(
            LoginItem(
                email = email,
                username = username,
                password = password,
                urls = emptyList(),
                totpUri = "",
                passkeys = emptyList(),
                autofillUrls = emptyList(),
            ),
        ),
        extraFields = emptyList(),
        platformSpecific = null,
        customIcon = null,
    )

    private fun withMetadata(
        item: ItemData,
        createdAt: ULong = 0uL,
        modifiedAt: ULong = 0uL,
        pinned: Boolean = false,
    ) = ItemWithMetadata(
        item = item,
        metadata = ItemMetadata(createdAt = createdAt, modifiedAt = modifiedAt, pinned = pinned),
    )

    private fun vaultData(name: String) = VaultData(
        name = name,
        description = "",
        displayPreferences = VaultDisplayPreferences(icon = VaultIcon.UNSPECIFIED, color = VaultColor.UNSPECIFIED),
    )

    @Test
    fun `login item round trips through export and import`() {
        val title = "My login"
        val email = "test@example.com"
        val password = "hunter2"
        val vaultName = "Personal"
        val item = loginItem(title, email, password)

        val exportInput = CxfExportInput(
            vaults = listOf(CxfVaultWithItems(vault = vaultData(vaultName), items = listOf(withMetadata(item)))),
            exporterRpId = "proton.me",
            exporterDisplayName = "Proton Pass",
            timestamp = 1700000000UL,
        )

        val exportResult = cxf.export(exportInput)
        assertThat(exportResult.warnings).isEmpty()

        val importResult = cxf.import(exportResult.payload)
        assertThat(importResult.warnings).isEmpty()
        assertThat(importResult.vaults).hasSize(1)

        val importedVault = importResult.vaults[0]
        assertThat(importedVault.vault?.name).isEqualTo(vaultName)
        assertThat(importedVault.items).hasSize(1)

        val importedLogin = importedVault.items[0].content as ItemContent.Login
        assertThat(importedLogin.v1.email).isEqualTo(email)
        assertThat(importedLogin.v1.password).isEqualTo(password)
    }

    @Test
    fun `item metadata maps to CXF creation, modification and favorite fields`() {
        val item = loginItem("Pinned login", "pinned@example.com", "hunter2")

        val exportInput = CxfExportInput(
            vaults = listOf(
                CxfVaultWithItems(
                    vault = vaultData("Personal"),
                    items = listOf(
                        withMetadata(item, createdAt = 1700000000UL, modifiedAt = 1700000100UL, pinned = true),
                    ),
                ),
            ),
            exporterRpId = "proton.me",
            exporterDisplayName = "Proton Pass",
            timestamp = 1700000000UL,
        )

        val exportResult = cxf.export(exportInput)
        assertThat(exportResult.warnings).isEmpty()
        assertThat(exportResult.payload).contains("\"creationAt\":1700000000")
        assertThat(exportResult.payload).contains("\"modifiedAt\":1700000100")
        assertThat(exportResult.payload).contains("\"favorite\":true")
    }

    @Test
    fun `login item with distinct email and username round trips without loss`() {
        val email = "alice@example.com"
        val username = "alice_the_gamer"
        val item = loginItem("Login with distinct email and username", email, "hunter2", username)

        val exportInput = CxfExportInput(
            vaults = listOf(CxfVaultWithItems(vault = vaultData("Personal"), items = listOf(withMetadata(item)))),
            exporterRpId = "proton.me",
            exporterDisplayName = "Proton Pass",
            timestamp = 1700000000UL,
        )

        val exportResult = cxf.export(exportInput)
        assertThat(exportResult.warnings).isEmpty()

        val importResult = cxf.import(exportResult.payload)
        assertThat(importResult.warnings).isEmpty()

        val importedLogin = importResult.vaults[0].items[0].content as ItemContent.Login
        assertThat(importedLogin.v1.email).isEqualTo(email)
        assertThat(importedLogin.v1.username).isEqualTo(username)
    }
}
