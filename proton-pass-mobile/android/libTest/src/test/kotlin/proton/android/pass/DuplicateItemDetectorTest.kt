package proton.android.pass

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import proton.android.pass.common.DuplicateItemGroup
import proton.android.pass.common.ItemForDuplicateDetection
import proton.android.pass.commonrust.DuplicateItemDetector
import proton.android.pass.types.ItemContent
import proton.android.pass.types.ItemData
import proton.android.pass.types.LoginItem
import proton.android.pass.types.NoteItem

class DuplicateItemDetectorTest {

    private val detector = DuplicateItemDetector()

    private fun loginItem(
        itemId: String,
        username: String = "",
        email: String = "",
        password: String,
        urls: List<String> = emptyList(),
    ) = ItemForDuplicateDetection(
        itemId = itemId,
        shareId = "share",
        item = ItemData(
            title = "title",
            note = "",
            itemUuid = "$itemId-uuid",
            content = ItemContent.Login(
                LoginItem(
                    email = email,
                    username = username,
                    password = password,
                    urls = urls,
                    totpUri = "",
                    passkeys = emptyList(),
                    autofillUrls = emptyList(),
                ),
            ),
            extraFields = emptyList(),
            platformSpecific = null,
            customIcon = null,
        ),
    )

    private fun noteItem(itemId: String, note: String) = ItemForDuplicateDetection(
        itemId = itemId,
        shareId = "share",
        item = ItemData(
            title = "title",
            note = note,
            itemUuid = "$itemId-uuid",
            content = ItemContent.Note(NoteItem()),
            extraFields = emptyList(),
            platformSpecific = null,
            customIcon = null,
        ),
    )

    private fun groupIds(groups: List<DuplicateItemGroup>) =
        groups.map { group -> group.items.map { it.itemId }.sorted() }.sortedBy { it.joinToString() }

    @Test
    fun `logins with same username, password and related urls are duplicates`() {
        val items = listOf(
            loginItem("1", username = "bob", password = "pw", urls = listOf("https://amazon.com/login")),
            loginItem("2", username = "bob", password = "pw", urls = listOf("https://www.amazon.com/account")),
        )

        val groups = detector.findDuplicates(items)

        assertThat(groupIds(groups)).isEqualTo(listOf(listOf("1", "2")))
    }

    @Test
    fun `logins with same identity and password but unrelated urls are not duplicates`() {
        val items = listOf(
            loginItem("1", username = "bob", password = "pw", urls = listOf("https://amazon.com/login")),
            loginItem("2", username = "bob", password = "pw", urls = listOf("https://uber.com/login")),
        )

        assertThat(detector.findDuplicates(items)).isEmpty()
    }

    @Test
    fun `logins matching by email instead of username are duplicates`() {
        val items = listOf(
            loginItem("1", email = "bob@proton.me", password = "pw"),
            loginItem("2", email = "bob@proton.me", password = "pw"),
        )

        val groups = detector.findDuplicates(items)

        assertThat(groupIds(groups)).isEqualTo(listOf(listOf("1", "2")))
    }

    @Test
    fun `logins with different identity are not duplicates`() {
        val items = listOf(
            loginItem("1", username = "bob", password = "pw"),
            loginItem("2", username = "alice", password = "pw"),
        )

        assertThat(detector.findDuplicates(items)).isEmpty()
    }

    @Test
    fun `logins are transitively grouped`() {
        val items = listOf(
            loginItem("1", username = "bob", password = "pw", urls = listOf("https://amazon.com")),
            loginItem(
                "2",
                username = "bob",
                password = "pw",
                urls = listOf("https://amazon.com", "https://uber.com"),
            ),
            loginItem("3", username = "bob", password = "pw", urls = listOf("https://uber.com")),
        )

        val groups = detector.findDuplicates(items)

        assertThat(groupIds(groups)).isEqualTo(listOf(listOf("1", "2", "3")))
    }

    @Test
    fun `notes with same note are duplicates`() {
        val items = listOf(noteItem("1", "same note"), noteItem("2", "same note"))

        val groups = detector.findDuplicates(items)

        assertThat(groupIds(groups)).isEqualTo(listOf(listOf("1", "2")))
    }

    @Test
    fun `notes with different note are not duplicates`() {
        val items = listOf(noteItem("1", "note a"), noteItem("2", "note b"))

        assertThat(detector.findDuplicates(items)).isEmpty()
    }

    @Test
    fun `different item types are never duplicates`() {
        val items = listOf(
            loginItem("1", username = "bob", email = "bob@proton.me", password = "pw"),
            noteItem("2", ""),
        )

        assertThat(detector.findDuplicates(items)).isEmpty()
    }

    @Test
    fun `items with no duplicates are excluded from results`() {
        val items = listOf(
            loginItem("1", username = "bob", password = "pw"),
            loginItem("2", username = "alice", password = "pw2"),
        )

        assertThat(detector.findDuplicates(items)).isEmpty()
    }
}
