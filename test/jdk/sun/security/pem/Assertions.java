import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.List;

public class Assertions {

    private static String msg(String s) {
        if (s == null) {
            return "";
        }
        return s + " - ";
    }

    static void assertNull(Object value) throws Exception {
        assertNull(value, null);
    }

    static void assertNull(Object value, String message) throws Exception {
        if (value != null) {
            throw new Exception(msg(message) + "expected null value, value: " + value);
        }
    }

    static void assertNotNull(Object value) throws Exception {
        assertNotNull(value, null);
    }

    static void assertNotNull(Object value, String message) throws Exception {
        if (value == null) {
            throw new Exception(msg(message) + "expected non-null value, value: " + value);
        }
    }

    static void assertFalse(boolean value) throws Exception {
        assertTrue(!value, null);
    }

    static void assertTrue(boolean value) throws Exception {
        assertTrue(value, null);
    }

    static void assertTrue(boolean value, String message) throws Exception {
        if (value != true) {
            throw new Exception(msg(message) + "expected value: true, value: " + value);
        }
    }

    static void assertEquals(int expectedValue, int value) throws Exception {
        assertEquals(expectedValue, value, null);
    }

    static void assertEquals(int expectedValue, int value, String message) throws Exception {
        if (value != expectedValue) {
            throw new Exception(msg(message) + "expected value: " + expectedValue + ", value: " + value);
        }
    }

    static void assertEquals(String expectedValue, String value) throws Exception {
        assertEquals(expectedValue, value, null);
    }

    static void assertEquals(String expectedValue, String value, String message) throws Exception {
        if (value == expectedValue) {
            return;
        }
        if (value == null || expectedValue == null || !expectedValue.equals(value)) {
            throw new Exception(msg(message) + "expected value: " + expectedValue + ", value: " + value);
        }
    }

    static void assertEquals(List<?> expectedValue, List<?> value) throws Exception {
        assertEquals(expectedValue, value, null);
    }

    static void assertEquals(List<?> expectedValue, List<?> value, String message) throws Exception {
        if (value == expectedValue) {
            return;
        }
        if (value == null || expectedValue == null || !expectedValue.equals(value)) {
            throw new Exception(msg(message) + "expected value: " + expectedValue + ", value: " + value);
        }
    }

    static void assertFilesEqual(File expectedFile, File realFile) throws Exception {
        assertFilesEqual(expectedFile.toPath(), realFile.toPath());
    }

    static void assertFilesEqual(Path expectedPath, Path realPath) throws Exception {
        assertArrayEquals(Files.readAllBytes(expectedPath), Files.readAllBytes(realPath));
    }

    static void assertArrayEquals(byte[] expectedValue, byte[] value) throws Exception {
        assertArrayEquals(expectedValue, value, null);
    }

    static void assertEquals(Object expectedValue, Object value) throws Exception {
        assertEquals(expectedValue, value, null);
    }

    static void assertEquals(Object expectedValue, Object value, String message) throws Exception {
        if (value == expectedValue) {
            return;
        }
        if (value == null || expectedValue == null || !expectedValue.equals(value)) {
            throw new Exception(msg(message) + "expected value: " + expectedValue + ", value: " + value);
        }
    }

    static void assertArrayEquals(byte[] expectedValue, byte[] value, String message) throws Exception {
        if (value == expectedValue) {
            return;
        }
        if (value == null || expectedValue == null || !Arrays.equals(expectedValue, value)) {
            throw new Exception(msg(message) + "expected value: " + Arrays.toString(expectedValue) + ", value: " + Arrays.toString(value));
        }
    }

    static void assertArrayEquals(Object[] expectedValue, Object[] value) throws Exception {
        assertArrayEquals(expectedValue, value, null);
    }

    static void assertArrayEquals(Object[] expectedValue, Object[] value, String message) throws Exception {
        if (value == expectedValue) {
            return;
        }
        if (value == null || expectedValue == null || !Arrays.equals(expectedValue, value)) {
            throw new Exception(msg(message) + "expected value: " + Arrays.toString(expectedValue) + ", value: " + Arrays.toString(value));
        }
    }
    static void fail() throws Exception {
        fail(null);
    }

    static void fail(String message) throws Exception {
        throw new Exception(message);
    }

}
