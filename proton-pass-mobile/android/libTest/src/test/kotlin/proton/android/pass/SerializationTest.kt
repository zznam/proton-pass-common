package proton.android.pass

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import proton.android.pass.commonrust.ProtonPassSerialization
import proton.android.pass.types.FolderData
import proton.android.pass.types.ItemContent
import proton.android.pass.types.ItemData
import proton.android.pass.types.LoginItem
import proton.android.pass.types.NoteItem
import proton.android.pass.types.VaultColor
import proton.android.pass.types.VaultData
import proton.android.pass.types.VaultDisplayPreferences
import proton.android.pass.types.VaultIcon

class SerializationTest {

    private val serialization = ProtonPassSerialization()

    private fun noteItem(title: String, note: String, customIcon: ByteArray? = null) = ItemData(
        title = title,
        note = note,
        itemUuid = "test-uuid",
        content = ItemContent.Note(NoteItem()),
        extraFields = emptyList(),
        platformSpecific = null,
        customIcon = customIcon,
    )

    private fun loginItem(title: String, urls: List<String>, customIcon: ByteArray? = null) = ItemData(
        title = title,
        note = "",
        itemUuid = "test-uuid-login",
        content = ItemContent.Login(
            LoginItem(
                email = "test@example.com",
                username = "testuser",
                password = "password123",
                urls = urls,
                totpUri = "",
                passkeys = emptyList(),
                autofillUrls = emptyList(),
            ),
        ),
        extraFields = emptyList(),
        platformSpecific = null,
        customIcon = customIcon,
    )

    private fun vaultData(name: String, description: String, icon: VaultIcon, color: VaultColor) = VaultData(
        name = name,
        description = description,
        displayPreferences = VaultDisplayPreferences(icon = icon, color = color),
    )

    @Test
    fun `item round trip serialize deserialize preserves all fields`() {
        val title = "My note"
        val note = "Some content"
        val item = noteItem(title, note)

        val bytes = serialization.itemDataSerialize(item)
        val result = serialization.itemDataDeserialize(bytes)

        assertThat(result.title).isEqualTo(title)
        assertThat(result.note).isEqualTo(note)
        assertThat(result.itemUuid).isEqualTo(item.itemUuid)
    }

    @Test
    fun `item round trip serialize deserialize preserves custom icon`() {
        val customIcon = byteArrayOf(1, 2, 3, 4)
        val item = noteItem("My note", "Some content", customIcon)

        val bytes = serialization.itemDataSerialize(item)
        val result = serialization.itemDataDeserialize(bytes)

        assertThat(result.customIcon).isEqualTo(customIcon)
    }

    @Test
    fun `item without custom icon round trips as null`() {
        val item = noteItem("My note", "Some content")

        val bytes = serialization.itemDataSerialize(item)
        val result = serialization.itemDataDeserialize(bytes)

        assertThat(result.customIcon).isNull()
    }

    @Test
    fun `item perform update clears custom icon when update omits it`() {
        val originalCustomIcon = byteArrayOf(1, 2, 3, 4)

        val original = noteItem("My note", "Some content", originalCustomIcon)
        val originalBytes = serialization.itemDataSerialize(original)

        val updated = noteItem("Updated title", "Some content")
        val updatedBytes = serialization.itemDataPerformUpdate(originalBytes, updated)
        val result = serialization.itemDataDeserialize(updatedBytes)

        assertThat(result.title).isEqualTo("Updated title")
        assertThat(result.customIcon).isNull()
    }

    @Test
    fun `item perform update replaces custom icon when update sets it`() {
        val originalCustomIcon = byteArrayOf(1, 2, 3, 4)
        val updatedCustomIcon = byteArrayOf(5, 6, 7, 8)

        val original = noteItem("My note", "Some content", originalCustomIcon)
        val originalBytes = serialization.itemDataSerialize(original)

        val updated = noteItem("My note", "Some content", updatedCustomIcon)
        val updatedBytes = serialization.itemDataPerformUpdate(originalBytes, updated)
        val result = serialization.itemDataDeserialize(updatedBytes)

        assertThat(result.customIcon).isEqualTo(updatedCustomIcon)
    }

    @Test
    fun `item perform update on basic field preserves other fields`() {
        val originalTitle = "Original title"
        val unchangedNote = "Original note"
        val updatedTitle = "Updated title"

        val original = noteItem(originalTitle, unchangedNote)
        val originalBytes = serialization.itemDataSerialize(original)

        val updated = noteItem(updatedTitle, unchangedNote)
        val updatedBytes = serialization.itemDataPerformUpdate(originalBytes, updated)
        val result = serialization.itemDataDeserialize(updatedBytes)

        assertThat(result.title).isEqualTo(updatedTitle)
        assertThat(result.note).isEqualTo(unchangedNote)
    }

    @Test
    fun `item perform update on repeated field replaces rather than appends`() {
        val title = "Login item"
        val originalUrls = listOf("https://example.com", "https://app.example.com")
        val updatedUrls = listOf("https://new.example.com")

        val original = loginItem(title, originalUrls)
        val originalBytes = serialization.itemDataSerialize(original)

        val updated = loginItem(title, updatedUrls)
        val updatedBytes = serialization.itemDataPerformUpdate(originalBytes, updated)
        val result = serialization.itemDataDeserialize(updatedBytes)

        val login = result.content as ItemContent.Login
        assertThat(login.v1.urls).containsExactlyElementsIn(updatedUrls)
    }

    @Test
    fun `login urls migrate to autofill urls on serialize`() {
        val urls = listOf("https://example.com", "https://app.example.com")
        val item = loginItem("Login item", urls)

        val bytes = serialization.itemDataSerialize(item)
        val result = serialization.itemDataDeserialize(bytes)

        val login = result.content as ItemContent.Login
        assertThat(login.v1.autofillUrls.map { it.url }).containsExactlyElementsIn(urls)
    }

    @Test
    fun `item content sealed class pattern matches on variants`() {
        val noteTitle = "Note title"
        val loginTitle = "Login title"
        val loginEmail = "test@example.com"

        val note = noteItem(noteTitle, "Note body")
        val login = loginItem(loginTitle, listOf("https://example.com"))

        val describe: (ItemData) -> String = { item ->
            when (val content = item.content) {
                is ItemContent.Login -> "login:${content.v1.email}"
                is ItemContent.Note -> "note"
                else -> "other"
            }
        }

        assertThat(describe(note)).isEqualTo("note")
        assertThat(describe(login)).isEqualTo("login:$loginEmail")
    }

    @Test
    fun `vault round trip`() {
        val vault = vaultData("My vault", "A description", VaultIcon.ICON5, VaultColor.COLOR3)

        val bytes = serialization.vaultDataSerialize(vault)
        val result = serialization.vaultDataDeserialize(bytes)

        assertThat(result).isEqualTo(vault)
    }

    @Test
    fun `vault perform update on display icon`() {
        val name = "My vault"
        val description = "A description"
        val unchangedColor = VaultColor.COLOR1
        val updatedIcon = VaultIcon.ICON5

        val original = vaultData(name, description, VaultIcon.CUSTOM, unchangedColor)
        val originalBytes = serialization.vaultDataSerialize(original)

        val updated = vaultData(name, description, updatedIcon, unchangedColor)
        val updatedBytes = serialization.vaultDataPerformUpdate(originalBytes, updated)
        val result = serialization.vaultDataDeserialize(updatedBytes)

        assertThat(result.displayPreferences.icon).isEqualTo(updatedIcon)
    }

    @Test
    fun `folder round trip`() {
        val folder = FolderData(name = "My folder")

        val bytes = serialization.folderDataSerialize(folder)
        val result = serialization.folderDataDeserialize(bytes)

        assertThat(result).isEqualTo(folder)
    }

    @Test
    fun `folder perform update on name`() {
        val updatedName = "Updated"

        val original = FolderData(name = "Original")
        val originalBytes = serialization.folderDataSerialize(original)

        val updated = FolderData(name = updatedName)
        val updatedBytes = serialization.folderDataPerformUpdate(originalBytes, updated)
        val result = serialization.folderDataDeserialize(updatedBytes)

        assertThat(result.name).isEqualTo(updatedName)
    }
}
