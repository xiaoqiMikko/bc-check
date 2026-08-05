package io.mikko.bccheck;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/** 版本比较与版本线归属。 */
public class VersionTest {

    @Test
    public void 段数不同时缺失段按0处理() {
        assertTrue(Version.compare("1.85", "1.85.1") < 0);
        assertTrue(Version.compare("2.73.12", "2.73.12.1") < 0);
        assertEquals(0, Version.compare("1.85", "1.85.0"));
    }

    @Test
    public void 数值比较不是字典序() {
        assertTrue(Version.compare("1.9", "1.10") < 0);
        assertTrue(Version.compare("1.80.1", "1.80.2") < 0);
        assertTrue(Version.compare("1.81", "1.80.9") > 0);
    }

    @Test
    public void 忽略后缀() {
        assertEquals(0, Version.compare("1.85-SNAPSHOT", "1.85"));
        assertEquals(0, Version.compare("1.81.redhat-00001", "1.81"));
    }

    /** FIPS 判定全靠版本线：1.0.x / 2.0.x / 2.1.x 是三条独立的数轴。 */
    @Test
    public void 版本线取前两段() {
        assertEquals("1.0", Version.lineOf("1.0.2.7"));
        assertEquals("2.0", Version.lineOf("2.0.2"));
        assertEquals("2.1", Version.lineOf("2.1.3"));
        assertEquals("2.73", Version.lineOf("2.73.12"));
        assertEquals("1.85", Version.lineOf("1.85"));
    }

    @Test
    public void 同线判断() {
        assertTrue(Version.sameLine("1.0.2.5", "1.0.2.7"));
        assertFalse(Version.sameLine("1.0.2.5", "2.0.2"));
        assertFalse(Version.sameLine("2.0.1", "2.1.3"));
    }

    @Test
    public void 解析不了的返回null() {
        assertNull(Version.parse(null));
        assertNull(Version.parse(""));
        assertNull(Version.parse("unknown"));
    }
}
