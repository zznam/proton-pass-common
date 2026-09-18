package proton.android.pass

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import proton.android.pass.commonrust.CxpExportHandler
import proton.android.pass.commonrust.CxpImportHandler
import proton.android.pass.common.CxfExportInput
import proton.android.pass.common.CxfVaultWithItems
import proton.android.pass.common.CxpCredentialType
import proton.android.pass.common.CxpException
import proton.android.pass.common.CxpExportRequest
import proton.android.pass.common.ItemMetadata
import proton.android.pass.common.ItemWithMetadata
import proton.android.pass.types.CardType
import proton.android.pass.types.CreditCardItem
import proton.android.pass.types.ItemContent
import proton.android.pass.types.ItemData
import proton.android.pass.types.LoginItem
import proton.android.pass.types.VaultColor
import proton.android.pass.types.VaultData
import proton.android.pass.types.VaultDisplayPreferences
import proton.android.pass.types.VaultIcon

class CxpTest {

    private fun loginItem(title: String, email: String, password: String) = ItemData(
        title = title,
        note = "",
        itemUuid = "test-uuid-login",
        content = ItemContent.Login(
            LoginItem(
                email = email,
                username = "",
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

    private fun creditCardItem(title: String) = ItemData(
        title = title,
        note = "",
        itemUuid = "test-uuid-credit-card",
        content = ItemContent.CreditCard(
            CreditCardItem(
                cardholderName = "Alice",
                cardType = CardType.VISA,
                number = "4111111111111111",
                verificationNumber = "123",
                expirationDate = "2030-01",
                pin = "",
            ),
        ),
        extraFields = emptyList(),
        platformSpecific = null,
        customIcon = null,
    )

    private fun exportInput(items: List<ItemData>, vaultName: String, exporterDisplayName: String) = CxfExportInput(
        vaults = listOf(
            CxfVaultWithItems(
                vault = VaultData(
                    name = vaultName,
                    description = "",
                    displayPreferences = VaultDisplayPreferences(icon = VaultIcon.UNSPECIFIED, color = VaultColor.UNSPECIFIED),
                ),
                items = items.map {
                    ItemWithMetadata(
                        item = it,
                        metadata = ItemMetadata(createdAt = 0uL, modifiedAt = 0uL, pinned = false),
                    )
                },
            ),
        ),
        exporterRpId = "other-app.example",
        exporterDisplayName = exporterDisplayName,
        timestamp = 1700000000UL,
    )

    private fun exportInput(item: ItemData, vaultName: String, exporterDisplayName: String) =
        exportInput(listOf(item), vaultName, exporterDisplayName)

    @Test
    fun `full export import self loop round trips`() {
        val email = "alice@example.com"
        val password = "hunter2"
        val vaultName = "Personal"

        val importer = CxpImportHandler()
        val exporter = CxpExportHandler()

        val request = importer.createExportRequest(
            CxpExportRequest(
                importerName = "Proton Pass",
                supportedCredentialTypes = listOf(CxpCredentialType.BASIC_AUTH),
            ),
        )

        val encryptedResponse = exporter.createExportResponse(
            request,
            exportInput(loginItem("My login", email, password), vaultName, "Other Password Manager"),
        )
        assertThat(encryptedResponse.warnings).isEmpty()

        val importResult = importer.processExportResponse(encryptedResponse.response)
        assertThat(importResult.warnings).isEmpty()
        assertThat(importResult.vaults).hasSize(1)

        val importedVault = importResult.vaults[0]
        assertThat(importedVault.vault?.name).isEqualTo(vaultName)

        val importedLogin = importedVault.items[0].content as ItemContent.Login
        assertThat(importedLogin.v1.email).isEqualTo(email)
        assertThat(importedLogin.v1.password).isEqualTo(password)
    }

    @Test(expected = CxpException.DeserializationException::class)
    fun `malformed export request throws deserialization exception`() {
        val exporter = CxpExportHandler()
        exporter.createExportResponse("not json", exportInput(loginItem("Login", "a@b.com", "pw"), "Vault", "Other App"))
    }

    @Test(expected = CxpException.InvalidState::class)
    fun `processing a response without a pending request throws invalid state`() {
        val importer = CxpImportHandler()
        importer.processExportResponse(byteArrayOf(1, 2, 3))
    }

    @Test(expected = CxpException.InvalidState::class)
    fun `processing a response twice throws invalid state on the second call`() {
        val importer = CxpImportHandler()
        val exporter = CxpExportHandler()

        val request = importer.createExportRequest(
            CxpExportRequest(importerName = "Proton Pass", supportedCredentialTypes = emptyList()),
        )
        val response = exporter.createExportResponse(
            request,
            exportInput(loginItem("Login", "a@b.com", "pw"), "Vault", "Other App"),
        ).response

        importer.processExportResponse(response)
        importer.processExportResponse(response)
    }

    @Test
    fun `parse export request summarizes importer and credential types`() {
        val importer = CxpImportHandler()
        val exporter = CxpExportHandler()

        val request = importer.createExportRequest(
            CxpExportRequest(
                importerName = "Proton Pass",
                supportedCredentialTypes = listOf(CxpCredentialType.BASIC_AUTH, CxpCredentialType.PASSKEY),
            ),
        )

        val summary = exporter.parseExportRequest(request)

        assertThat(summary.importerName).isEqualTo("Proton Pass")
        assertThat(summary.requestedCredentialTypes).containsExactly(
            CxpCredentialType.BASIC_AUTH,
            CxpCredentialType.PASSKEY,
        )
        assertThat(summary.requestsAllCredentialTypes).isFalse()
    }

    @Test
    fun `parse export request reports no restriction when credential types are absent`() {
        val importer = CxpImportHandler()
        val exporter = CxpExportHandler()

        val request = importer.createExportRequest(
            CxpExportRequest(importerName = "Proton Pass", supportedCredentialTypes = emptyList()),
        )

        val summary = exporter.parseExportRequest(request)

        assertThat(summary.requestedCredentialTypes).isEmpty()
        assertThat(summary.requestsAllCredentialTypes).isTrue()
    }

    @Test(expected = CxpException.DeserializationException::class)
    fun `parse export request throws deserialization exception on malformed json`() {
        val exporter = CxpExportHandler()
        exporter.parseExportRequest("not json")
    }

    @Test
    fun `create export response only includes requested credential types`() {
        val importer = CxpImportHandler()
        val exporter = CxpExportHandler()

        val request = importer.createExportRequest(
            CxpExportRequest(importerName = "Proton Pass", supportedCredentialTypes = listOf(CxpCredentialType.CREDIT_CARD)),
        )

        val items = listOf(loginItem("My login", "alice@example.com", "hunter2"), creditCardItem("My card"))
        val response = exporter.createExportResponse(request, exportInput(items, "Personal", "Other App"))

        val importResult = importer.processExportResponse(response.response)
        assertThat(importResult.vaults[0].items).hasSize(1)
        assertThat(importResult.vaults[0].items[0].content).isInstanceOf(ItemContent.CreditCard::class.java)
    }

    @Test
    fun `create export response includes everything when request has no restriction`() {
        val importer = CxpImportHandler()
        val exporter = CxpExportHandler()

        val request = importer.createExportRequest(
            CxpExportRequest(importerName = "Proton Pass", supportedCredentialTypes = emptyList()),
        )

        val items = listOf(loginItem("My login", "alice@example.com", "hunter2"), creditCardItem("My card"))
        val response = exporter.createExportResponse(request, exportInput(items, "Personal", "Other App"))

        val importResult = importer.processExportResponse(response.response)
        assertThat(importResult.vaults[0].items).hasSize(2)
    }

    @Test(expected = CxpException.UnsupportedHpkeParameters::class)
    fun `complete export rejects a response with an unsupported version`() {
        val importer = CxpImportHandler()
        importer.createExportRequest(
            CxpExportRequest(importerName = "Proton Pass", supportedCredentialTypes = emptyList()),
        )

        val response = """
            {
                "version": 7,
                "hpke": { "mode": "base", "kem": 32, "kdf": 1, "aead": 3, "key": null },
                "exporter": "Other App",
                "payload": "AAAA",
                "archive": "deflate"
            }
        """.trimIndent()

        importer.processExportResponse(response.toByteArray())
    }
}
