package io.mikko.bccheck;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/** 产品线识别 —— 判定的第一步，认错线后面全错。 */
public class CoordinateTest {

    @Test
    public void 识别BC线() {
        assertEquals(Coordinate.Line.BC, Coordinate.of("bcprov-jdk18on").line);
        assertEquals(Coordinate.Line.BC, Coordinate.of("bcprov-jdk15to18").line);
        assertEquals(Coordinate.Line.BC, Coordinate.of("bcprov-jdk15on").line);
        assertEquals(Coordinate.Line.BC, Coordinate.of("bcpkix-jdk18on").line);
        assertEquals(Coordinate.Line.BC, Coordinate.of("bctls-jdk18on").line);
    }

    @Test
    public void 识别LTS线() {
        assertEquals(Coordinate.Line.LTS, Coordinate.of("bcprov-lts8on").line);
        assertEquals(Coordinate.Line.LTS, Coordinate.of("bcpkix-lts8on").line);
        assertEquals("bcpkix", Coordinate.of("bcpkix-lts8on").module);
    }

    @Test
    public void 识别FIPS线() {
        assertEquals(Coordinate.Line.FIPS, Coordinate.of("bc-fips").line);
        assertEquals(Coordinate.Line.FIPS, Coordinate.of("bctls-fips").line);
        assertEquals(Coordinate.Line.FIPS, Coordinate.of("bcutil-fips").line);
    }

    /** FIPS 版把 provider 与 util 合并进单个 bc-fips，模块归到 bcprov。 */
    @Test
    public void bcFips归到bcprov模块() {
        assertEquals("bcprov", Coordinate.of("bc-fips").module);
        assertEquals("bctls", Coordinate.of("bctls-fips").module);
    }

    /** -ext / -debug 只是打包变体，与漏洞判定无关。 */
    @Test
    public void 打包变体归一到同一模块() {
        assertEquals("bcprov", Coordinate.of("bcprov-ext-jdk18on").module);
        assertEquals("bcprov", Coordinate.of("bcprov-debug-jdk18on").module);
        assertEquals("bcprov", Coordinate.of("bcprov-jdk18on").module);
    }

    @Test
    public void 大小写不敏感() {
        assertEquals(Coordinate.Line.BC, Coordinate.of("BCPROV-JDK18ON").line);
    }

    @Test
    public void 非BC构件返回null() {
        assertNull(Coordinate.of("fastjson"));
        assertNull(Coordinate.of("spring-core"));
        assertNull(Coordinate.of(""));
        assertNull(Coordinate.of(null));
    }
}
