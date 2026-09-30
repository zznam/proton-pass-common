package proton.android.pass

import com.google.common.truth.Truth.assertThat
import org.junit.Test
import proton.android.pass.commonrust.GunzipException
import proton.android.pass.commonrust.PassGzip
import java.io.ByteArrayOutputStream
import java.util.zip.GZIPOutputStream
import kotlin.test.assertFailsWith

class PassGzipTest {

    private fun gzip(data: ByteArray): ByteArray {
        val output = ByteArrayOutputStream()
        GZIPOutputStream(output).use { it.write(data) }
        return output.toByteArray()
    }

    @Test
    fun `can gunzip data`() {
        val original = "hello world".toByteArray()

        val result = PassGzip().gunzip(gzip(original))

        assertThat(result).isEqualTo(original)
    }

    @Test
    fun `invalid data fails`() {
        assertFailsWith<GunzipException.Decompress> {
            PassGzip().gunzip("not gzip".toByteArray())
        }
    }

    @Test
    fun `output larger than 10MB fails`() {
        val big = ByteArray(10 * 1024 * 1024 + 1)

        assertFailsWith<GunzipException.OutputTooBig> {
            PassGzip().gunzip(gzip(big))
        }
    }
}
