package io.mikko.bccheck;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

/**
 * 判定引擎的自校验。
 *
 * <p><b>这个测试类是本工具最重要的部分。</b>工具的全部价值押在「判定是对的」上面：
 * 第一注的教训是<b>判定规则错了不是误报，是让用户做错事</b>。
 * 因此这里的每个用例都直接对应官方 wiki 上写死的一条事实，而不是对着实现反推期望值。
 */
public class JudgeTest {

    private static Judge.Assessment assess(String artifactId, String version) {
        Coordinate c = Coordinate.of(artifactId);
        assertNotNull("认不出坐标：" + artifactId, c);
        return Judge.assess(c, version);
    }

    private static boolean hits(Judge.Assessment a, String cve) {
        for (Judge.Hit h : a.hits) {
            if (h.rule.cve.equals(cve)) {
                return true;
            }
        }
        return false;
    }

    // ---------- 一、有 CVE 只影响单一产品线，一刀切必漏 ----------

    /**
     * 官方原文：CVE-2026-8149「Issue affecting: BC-LTS 2.73.0 to 2.73.10」。
     * 它<b>压根不影响 BC 线</b> —— 盯着「1.85」这个版本号的人永远发现不了它。
     */
    @Test
    public void cve8149只影响LTS线() {
        assertFalse(hits(assess("bcprov-jdk18on", "1.81"), "CVE-2026-8149"));
        assertFalse(hits(assess("bcprov-jdk18on", "1.60"), "CVE-2026-8149"));
        assertTrue(hits(assess("bcprov-lts8on", "2.73.5"), "CVE-2026-8149"));
        assertTrue(hits(assess("bcprov-lts8on", "2.73.10"), "CVE-2026-8149"));
        // 2.73.11 是官方给的修复版
        assertFalse(hits(assess("bcprov-lts8on", "2.73.11"), "CVE-2026-8149"));
    }

    /** 官方原文：CVE-2026-59652 / 59644 / 12852 只写了「BC before 1.85」，不影响 LTS。 */
    @Test
    public void 只影响BC线的CVE不该报给LTS用户() {
        Judge.Assessment lts = assess("bcprov-lts8on", "2.73.5");
        assertFalse(hits(lts, "CVE-2026-59652"));
        assertFalse(hits(lts, "CVE-2026-59644"));
        assertFalse(hits(lts, "CVE-2026-12852"));
    }

    // ---------- 二、FIPS：未被列出的版本线 = 不受影响 ----------

    /**
     * 官方对 CVE-2026-58062 与 58060 写的是「bc-fips 2.0.2 and 2.1.3」，<b>没有 1.0.x</b>，
     * 意思是 1.0.x 线不受影响；而 CVE-2026-8763 写的是「1.0.2.7, 2.0.2 and 2.1.3」，1.0.x 受影响。
     * 同一个 artifact、同一个版本，四条 critical 给出四套答案。
     */
    @Test
    public void fips未列出的版本线不受影响() {
        Judge.Assessment fips10 = assess("bc-fips", "1.0.2.5");
        assertTrue("8763 明确列了 1.0.2.7", hits(fips10, "CVE-2026-8763"));
        assertFalse("58062 只列了 2.0.2 / 2.1.3", hits(fips10, "CVE-2026-58062"));
        assertFalse("58060 只列了 2.0.2 / 2.1.3", hits(fips10, "CVE-2026-58060"));

        Judge.Assessment fips20 = assess("bc-fips", "2.0.1");
        assertTrue(hits(fips20, "CVE-2026-58062"));
        assertTrue(hits(fips20, "CVE-2026-8763"));
    }

    /** 官方原文：CVE-2026-59650「BC before 1.85, BC-LTS before 2.73.12」—— FIPS 完全不受影响。 */
    @Test
    public void cve59650不影响FIPS() {
        assertFalse(hits(assess("bc-fips", "1.0.2.5"), "CVE-2026-59650"));
        assertFalse(hits(assess("bc-fips", "2.0.1"), "CVE-2026-59650"));
        assertTrue(hits(assess("bcprov-jdk18on", "1.84"), "CVE-2026-59650"));
        assertTrue(hits(assess("bcprov-lts8on", "2.73.11"), "CVE-2026-59650"));
    }

    /**
     * 官方原文：CVE-2026-59638 的 FIPS 侧要查的是 <b>bctls-fips</b>，不是 bcprov ——
     * artifact 直接从加密核心换成了 TLS 模块。只盯着 bc-fips 的人查不到它。
     */
    @Test
    public void cve59638在FIPS侧换了artifact() {
        assertFalse(hits(assess("bc-fips", "1.0.2.5"), "CVE-2026-59638"));
        assertTrue(hits(assess("bctls-fips", "1.0.20"), "CVE-2026-59638"));
        // 官方写「1.0.24 (from 1.0.7)」，1.0.5 早于起始受影响版本
        assertFalse(hits(assess("bctls-fips", "1.0.5"), "CVE-2026-59638"));
        assertFalse(hits(assess("bctls-fips", "1.0.24"), "CVE-2026-59638"));
    }

    /** 官方对 bcutil-fips 只给了「2.0.7 and 2.1.7」，这个 artifact 根本没有 1.0.x 线。 */
    @Test
    public void bcutilFips没有1_0线() {
        assertFalse(hits(assess("bcutil-fips", "1.0.5"), "CVE-2026-59645"));
        assertTrue(hits(assess("bcutil-fips", "2.0.5"), "CVE-2026-59645"));
        assertFalse(hits(assess("bcutil-fips", "2.0.7"), "CVE-2026-59645"));
    }

    // ---------- 三、起始受影响版本：不是「全版本受影响」 ----------

    /** 官方原文：CVE-2026-59638「BC before 1.85 (from 1.61)」。1.60 不受影响。 */
    @Test
    public void 起始受影响版本生效() {
        assertFalse(hits(assess("bcprov-jdk18on", "1.60"), "CVE-2026-59638"));
        assertTrue(hits(assess("bcprov-jdk18on", "1.61"), "CVE-2026-59638"));

        // CVE-2026-58062「from 1.66」
        assertFalse(hits(assess("bcprov-jdk18on", "1.65"), "CVE-2026-58062"));
        assertTrue(hits(assess("bcprov-jdk18on", "1.66"), "CVE-2026-58062"));

        // CVE-2026-59643「from 1.81」
        assertFalse(hits(assess("bcprov-jdk18on", "1.80"), "CVE-2026-59643"));
        assertTrue(hits(assess("bcprov-jdk18on", "1.81"), "CVE-2026-59643"));
    }

    // ---------- 四、老分支的闭区间修复版 ----------

    /**
     * 官方原文：CVE-2026-0636 影响「BC 1.74 to 1.80.1, BC 1.81, BC 1.82 to BC 1.83」，
     * 修复版是 1.80.2 / 1.81.1 / 1.84 三个分支版本 —— <b>区间是断开的</b>。
     * 1.80.2 已修，但它仍小于 1.85，会命中另一批 CVE。
     */
    @Test
    public void 老分支闭区间与分支修复版() {
        assertTrue(hits(assess("bcprov-jdk18on", "1.80.1"), "CVE-2026-0636"));
        assertFalse("1.80.2 是该分支的修复版", hits(assess("bcprov-jdk18on", "1.80.2"), "CVE-2026-0636"));
        assertTrue(hits(assess("bcprov-jdk18on", "1.81"), "CVE-2026-0636"));
        assertFalse(hits(assess("bcprov-jdk18on", "1.81.1"), "CVE-2026-0636"));
        assertTrue(hits(assess("bcprov-jdk18on", "1.83"), "CVE-2026-0636"));
        assertFalse(hits(assess("bcprov-jdk18on", "1.84"), "CVE-2026-0636"));

        // 但 1.80.2 依然受「before 1.85」那批影响，不能因为修了 0636 就以为安全了
        assertTrue(hits(assess("bcprov-jdk18on", "1.80.2"), "CVE-2026-12185"));
    }

    /**
     * CVE-2026-5588 是唯一一条 FIPS 侧用闭区间写法的：
     * 「BCPKIX-FIPS 2.0.6 to 2.0.10」，且 LTS 侧只影响 bcpkix 模块。
     */
    @Test
    public void cve5588的闭区间与模块限定() {
        assertTrue(hits(assess("bcpkix-fips", "2.0.8"), "CVE-2026-5588"));
        assertTrue(hits(assess("bcpkix-fips", "2.0.10"), "CVE-2026-5588"));
        assertFalse(hits(assess("bcpkix-fips", "2.0.11"), "CVE-2026-5588"));
        assertFalse("2.0.5 早于起始受影响版本", hits(assess("bcpkix-fips", "2.0.5"), "CVE-2026-5588"));

        // LTS 侧官方写的是 BCPKIX-LTS，只影响 bcpkix 这一个模块
        assertTrue(hits(assess("bcpkix-lts8on", "2.73.8"), "CVE-2026-5588"));
        assertFalse(hits(assess("bcprov-lts8on", "2.73.8"), "CVE-2026-5588"));
    }

    // ---------- 五、修复版建议 ----------

    @Test
    public void 修复版建议按产品线各不相同() {
        assertEquals("1.85", assess("bcprov-jdk18on", "1.81").fixVersion);
        assertEquals("2.73.12", assess("bcprov-lts8on", "2.73.5").fixVersion);
        assertEquals("1.0.2.7", assess("bc-fips", "1.0.2.5").fixVersion);
        assertEquals("2.0.2", assess("bc-fips", "2.0.1").fixVersion);
        assertEquals("1.0.24", assess("bctls-fips", "1.0.20").fixVersion);
        assertEquals("2.1.12", assess("bcpkix-fips", "2.1.8").fixVersion);
    }

    // ---------- 六、修复版本应当清零 ----------

    @Test
    public void 修复版不再命中任何CVE() {
        assertTrue(assess("bcprov-jdk18on", "1.85").hits.isEmpty());
        assertTrue(assess("bcpkix-jdk18on", "1.85").hits.isEmpty());
        assertTrue(assess("bcprov-lts8on", "2.73.12").hits.isEmpty());
        assertTrue(assess("bc-fips", "2.1.3").hits.isEmpty());
        assertTrue(assess("bctls-fips", "2.1.24").hits.isEmpty());
        assertEquals(Severity.OK, assess("bcprov-jdk18on", "1.85").severity());
    }

    /** 1.85.1 是打包修正、与 1.85 同属一次 release，判定上不应比 1.85 差。 */
    @Test
    public void 版本1_85_1同样是安全的() {
        assertTrue(assess("bcprov-jdk15to18", "1.85.1").hits.isEmpty());
    }

    // ---------- 七、critical 计数 ----------

    @Test
    public void 四条critical都能被BC线老版本命中() {
        Judge.Assessment a = assess("bcprov-jdk18on", "1.80");
        assertTrue(hits(a, "CVE-2026-58062"));
        assertTrue(hits(a, "CVE-2026-8763"));
        assertTrue(hits(a, "CVE-2026-59650"));
        assertTrue(hits(a, "CVE-2026-59638"));
        assertEquals(4, a.criticalCount());
        assertEquals(Severity.CRITICAL, a.severity());
    }

    // ---------- 八、模块推断只降噪，不改判定 ----------

    /**
     * 官方对非 FIPS 线只写「before 1.85」，不指明 artifact。
     * 工具按 FIPS 侧点名的 artifact 反推模块，但这只能用来排优先级 ——
     * 被标为「大概率属其他模块」的 CVE <b>仍然计入命中</b>，不能替官方宣布用户安全。
     */
    @Test
    public void 模块推断不影响是否命中() {
        Judge.Assessment prov = assess("bcprov-jdk18on", "1.80");
        boolean sawOther = false;
        for (Judge.Hit h : prov.hits) {
            // 59641 的 FIPS 侧点名 bcmail/bcjmail，对 bcprov 用户应标为大概率属其他模块
            if (h.rule.cve.equals("CVE-2026-59641")) {
                assertTrue(h.otherModuleLikely);
                sawOther = true;
            }
        }
        assertTrue("应当命中 CVE-2026-59641 并标注模块推断", sawOther);
        assertTrue(prov.relevantCount() < prov.hits.size());

        // FIPS 线按 artifact 精确匹配，不做推断
        for (Judge.Hit h : assess("bc-fips", "1.0.2.5").hits) {
            assertFalse(h.otherModuleLikely);
        }
    }

    // ---------- 九、规则表完整性（防解析静默失效） ----------

    /**
     * 每条规则至少要覆盖一条产品线。
     *
     * <p>防的是这种事故：抓取或解析出错导致某条规则的区间为空，
     * 于是它对任何版本都不命中 —— 而<b>测试全绿、报告干净，谁也发现不了</b>。
     */
    @Test
    public void 每条规则至少覆盖一条产品线() {
        assertEquals("官方 wiki 上 2026 年共 37 条", 37, CveTable.rules().size());
        for (CveTable.Rule r : CveTable.rules()) {
            boolean any = r.bc.length > 0 || r.lts.length > 0 || !r.fips.isEmpty();
            assertTrue(r.cve + " 的受影响范围解析为空", any);
            assertTrue(r.cve + " 缺少官方原文", r.affecting.length() > 0 && r.fixed.length() > 0);
        }
    }

    /** 每条影响 BC 线的规则，都应当能被某个足够老的 BC 版本命中。 */
    @Test
    public void BC线规则都能被老版本命中() {
        Judge.Assessment old = assess("bcprov-jdk18on", "1.83");
        for (CveTable.Rule r : CveTable.rules()) {
            if (r.bc.length == 0) {
                continue;
            }
            assertTrue(r.cve + " 影响 BC 线，却没被 1.83 命中", hits(old, r.cve));
        }
    }
}
