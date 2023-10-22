public class Assertions {

    private static String msg(String s) {
        if (s == null) {
            return "";
        }
        return s + " - ";
    }

    static void assertNotNull(Object value) throws Exception {
        assertNotNull(value, null);
    }

    static void assertNotNull(Object value, String message) throws Exception {
        if (value == null) {
            throw new Exception(msg(message) + "expected non-null value, value: " + value);
        }
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

    static void fail() throws Exception {
        fail(null);
    }

    static void fail(String message) throws Exception {
        throw new Exception(message);
    }

}
