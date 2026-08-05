package io.mikko.bccheck;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 判定引擎：给定一个构件坐标与版本，算出它命中哪些 CVE、该升到哪个版本。
 *
 * <p>依据全部来自 {@link CveTable}（由官方 wiki 逐条抓取生成），本类只负责比对，不含任何写死的版本号。
 *
 * <p><b>三条产品线的判定方式完全不同</b>：
 * <ul>
 *   <li>BC 线：官方给的是「before 1.85」或若干闭区间（1.74–1.80.1 这种老分支修复）。</li>
 *   <li>BC-LTS 线：另一套版本号 2.73.x。有 CVE 只影响这条线（{@code CVE-2026-8149}），
 *       也有 CVE 只影响这条线的某个模块（{@code CVE-2026-5588} 只影响 bcpkix-lts）。</li>
 *   <li>FIPS 线：按 artifact 逐个匹配，且<b>每个 artifact 的每条版本线各有各的修复版</b>。
 *       官方没列出的版本线 = 不受影响，这是本工具最主要的判定价值。</li>
 * </ul>
 */
public final class Judge {

    /** 从 Fixed versions 原文里取 BC 线修复版，如「BC 1.80.2, BC 1.81.1, BC 1.84」。 */
    private static final Pattern FIX_BC = Pattern.compile("\\bBC (\\d[\\d.]*)");
    /**
     * 取 BC-LTS 修复版。
     *
     * <p>{@code BC[A-Z]*} 那段不能省：{@code CVE-2026-5588} 的修复版官方写作
     * 「BCPKIX-LTS 2.73.11」而不是「BC-LTS 2.73.11」，只认 {@code BC-LTS} 会漏掉它。
     */
    private static final Pattern FIX_LTS = Pattern.compile("\\bBC[A-Z]*-LTS (\\d[\\d.]*)");

    private Judge() {
    }

    /** 一条命中的 CVE。 */
    public static final class Hit {
        public final CveTable.Rule rule;
        /**
         * true 表示：官方对本产品线只写了「before 1.85」不指明 artifact，
         * 而按 FIPS 侧点名的 artifact 反推，这条 CVE 大概率出在<b>别的模块</b>。
         *
         * <p>⚠️ 这是<b>推断</b>，只用于降噪排序，不用于判定安全 ——
         * 官方原文没说你这个模块不受影响，工具就不能替官方说。
         */
        public final boolean otherModuleLikely;

        Hit(CveTable.Rule rule, boolean otherModuleLikely) {
            this.rule = rule;
            this.otherModuleLikely = otherModuleLikely;
        }
    }

    /** 一个构件的完整判定结果。 */
    public static final class Assessment {
        public final Coordinate coordinate;
        public final String version;
        public final List<Hit> hits;
        /** 建议升级到的版本；无命中或算不出时为 null。 */
        public final String fixVersion;
        /** 版本号无法解析，判定不可靠。 */
        public final boolean versionUnknown;

        Assessment(Coordinate coordinate, String version, List<Hit> hits,
                   String fixVersion, boolean versionUnknown) {
            this.coordinate = coordinate;
            this.version = version;
            this.hits = hits;
            this.fixVersion = fixVersion;
            this.versionUnknown = versionUnknown;
        }

        public int criticalCount() {
            int n = 0;
            for (Hit h : hits) {
                if (h.rule.critical) {
                    n++;
                }
            }
            return n;
        }

        /** 官方原文点名了本模块、或压根没给模块线索的命中数 —— 最该优先处理的那批。 */
        public int relevantCount() {
            int n = 0;
            for (Hit h : hits) {
                if (!h.otherModuleLikely) {
                    n++;
                }
            }
            return n;
        }

        public Severity severity() {
            if (versionUnknown) {
                return Severity.UNKNOWN;
            }
            if (criticalCount() > 0) {
                return Severity.CRITICAL;
            }
            return hits.isEmpty() ? Severity.OK : Severity.HIGH;
        }
    }

    /** 判定一个构件。{@code version} 为 null 或无法解析时返回 UNKNOWN 结果。 */
    public static Assessment assess(Coordinate c, String version) {
        if (c == null) {
            throw new IllegalArgumentException("coordinate 不能为 null");
        }
        if (Version.parse(version) == null) {
            return new Assessment(c, version, new ArrayList<Hit>(), null, true);
        }

        List<Hit> hits = new ArrayList<Hit>();
        String fix = null;

        for (CveTable.Rule r : CveTable.rules()) {
            boolean affected;
            String candidateFix;
            switch (c.line) {
                case BC:
                    affected = inRanges(version, r.bc, r.bcBefore);
                    candidateFix = affected ? maxMatch(FIX_BC, r.fixed) : null;
                    break;
                case LTS:
                    // 有 CVE 只影响 LTS 线的某个模块，模块对不上就不受影响
                    affected = (r.ltsModule == null || r.ltsModule.equals(c.module))
                            && inRanges(version, r.lts, r.ltsBefore);
                    candidateFix = affected ? maxMatch(FIX_LTS, r.fixed) : null;
                    break;
                case FIPS:
                    CveTable.F f = r.fips.get(c.artifactId);
                    affected = f != null && fipsAffected(version, f);
                    candidateFix = affected ? fipsFix(version, f) : null;
                    break;
                default:
                    affected = false;
                    candidateFix = null;
            }
            if (!affected) {
                continue;
            }
            hits.add(new Hit(r, otherModuleLikely(c, r)));
            if (candidateFix != null && (fix == null || Version.compare(candidateFix, fix) > 0)) {
                fix = candidateFix;
            }
        }
        return new Assessment(c, version, hits, fix, false);
    }

    /**
     * BC / BC-LTS 线的区间判定。
     *
     * @param before true 表示「before X」型（上界不含）；false 表示闭区间（上界含）
     */
    private static boolean inRanges(String version, CveTable.V[] ranges, boolean before) {
        for (CveTable.V v : ranges) {
            if (v.from != null && Version.compare(version, v.from) < 0) {
                continue;
            }
            int c = Version.compare(version, v.upper);
            if (before ? c < 0 : c <= 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * FIPS 判定。
     *
     * <p>核心规则：只拿<b>同一条版本线</b>的条目比对。官方写「bc-fips 2.0.2 and 2.1.3」
     * 而没写 1.0.x，就意味着 1.0.x 线不受这条 CVE 影响 —— 此时同线条目找不到，判定为不受影响。
     */
    private static boolean fipsAffected(String version, CveTable.F f) {
        for (CveTable.V v : f.lines) {
            if (!Version.sameLine(version, v.upper)) {
                continue;
            }
            if (v.from != null && Version.compare(version, v.from) < 0) {
                continue;
            }
            int c = Version.compare(version, v.upper);
            if (f.before ? c < 0 : c <= 0) {
                return true;
            }
        }
        return false;
    }

    /** 取该 FIPS artifact 在当前版本线上的修复版。 */
    private static String fipsFix(String version, CveTable.F f) {
        String best = null;
        for (CveTable.V v : f.lines) {
            if (!Version.sameLine(version, v.upper)) {
                continue;
            }
            if (best == null || Version.compare(v.upper, best) > 0) {
                best = v.upper;
            }
        }
        // 闭区间型（如 CVE-2026-5588）的区间上界是「最后一个受影响版本」，不是修复版，
        // 修复版只写在 Fixed versions 原文里，交由调用方从原文读取。
        return f.before ? best : null;
    }

    /**
     * 按 FIPS 侧点名的 artifact 反推：这条 CVE 是不是大概率出在别的模块。
     *
     * <p>只对 BC / BC-LTS 线有意义 —— FIPS 线本来就是按 artifact 精确匹配的。
     */
    private static boolean otherModuleLikely(Coordinate c, CveTable.Rule r) {
        if (c.line == Coordinate.Line.FIPS || r.modules.isEmpty()) {
            return false;
        }
        return !r.modules.contains(c.module);
    }

    /** 在文本里找出所有匹配的版本号，返回最大的那个。 */
    private static String maxMatch(Pattern p, String text) {
        Matcher m = p.matcher(text);
        String best = null;
        while (m.find()) {
            String v = m.group(1);
            if (best == null || Version.compare(v, best) > 0) {
                best = v;
            }
        }
        return best;
    }
}
