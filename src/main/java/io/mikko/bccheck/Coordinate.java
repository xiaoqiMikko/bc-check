package io.mikko.bccheck;

/**
 * 一个 Bouncy Castle 构件的身份：属于哪条产品线、哪个模块。
 *
 * <p><b>为什么这一步是整个工具的关键</b>：官方所有 CVE 描述统一写
 * 「Bouncy Castle for Java before 1.85」，但真正在用的人里 ——
 * 用 BC-LTS 的版本号是 {@code 2.73.x}，用 FIPS 的是 {@code 1.0.x / 2.0.x / 2.1.x}。
 * 拿「before 1.85」去比对，三条产品线里有两条完全无从判断。
 * 判定的第一件事必须是搞清楚「你手上这个 jar 到底属于哪条线」。
 */
public final class Coordinate {

    /** 产品线。 */
    public enum Line {
        /** 常规版：{@code *-jdk18on} / {@code *-jdk15to18} / {@code *-jdk15on} / {@code *-jdk14}，版本形如 1.85。 */
        BC("BC"),
        /** 长期支持版：{@code *-lts8on}，版本形如 2.73.12。 */
        LTS("BC-LTS"),
        /** FIPS 认证版：{@code bc-fips} 等，版本形如 1.0.2.7 / 2.0.2 / 2.1.3。 */
        FIPS("BC-FJA(FIPS)");

        private final String label;

        Line(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    /** 完整 artifactId，如 {@code bcprov-jdk18on}。 */
    public final String artifactId;
    public final Line line;
    /**
     * 归一化后的模块名：bcprov / bcpkix / bctls / bcutil / bcpg / bcmail / bcjmail。
     *
     * <p>{@code bcprov-ext-jdk18on} 与 {@code bcprov-jdk18on} 归一到同一个 {@code bcprov}；
     * FIPS 线的 {@code bc-fips} 归一到 {@code bcprov} —— FIPS 版把 prov 与 util 合并进了一个包。
     */
    public final String module;

    private Coordinate(String artifactId, Line line, String module) {
        this.artifactId = artifactId;
        this.line = line;
        this.module = module;
    }

    /**
     * 从 artifactId 识别产品线与模块。
     *
     * @return 不是 Bouncy Castle 构件时返回 null
     */
    public static Coordinate of(String artifactId) {
        if (artifactId == null) {
            return null;
        }
        String a = artifactId.trim().toLowerCase();
        if (a.isEmpty()) {
            return null;
        }

        if (a.endsWith("-fips") || "bc-fips".equals(a)) {
            String base = a.substring(0, a.length() - "-fips".length());
            // FIPS 版把 provider 与 util 合并成单个 bc-fips，模块归到 bcprov
            String module = "bc".equals(base) ? "bcprov" : base;
            return new Coordinate(a, Line.FIPS, module);
        }

        int cut = a.indexOf("-lts");
        if (cut > 0) {
            return new Coordinate(a, Line.LTS, normalizeModule(a.substring(0, cut)));
        }

        cut = a.indexOf("-jdk");
        if (cut > 0) {
            return new Coordinate(a, Line.BC, normalizeModule(a.substring(0, cut)));
        }

        // 裸模块名（bcprov / bcpkix / ...）判为 BC 线。
        // 依据：官方 jar 的 MANIFEST 里，Bundle-SymbolicName 对 BC 线写的就是裸名（bcprov），
        // 而 LTS 线写作 bcprov-lts8on、FIPS 线写作 bc-fips —— 那两条线都自带后缀，
        // 所以「没有后缀」本身就是 BC 线的标志。
        if (isKnownModule(a)) {
            return new Coordinate(a, Line.BC, a);
        }

        return null;
    }

    /** Bouncy Castle 的模块名全集。 */
    private static boolean isKnownModule(String s) {
        return "bcprov".equals(s) || "bcpkix".equals(s) || "bctls".equals(s)
                || "bcutil".equals(s) || "bcpg".equals(s) || "bcmail".equals(s)
                || "bcjmail".equals(s);
    }

    /** 去掉 {@code -ext} / {@code -debug} 这类打包变体后缀，它们与漏洞判定无关。 */
    private static String normalizeModule(String base) {
        String m = base;
        while (true) {
            if (m.endsWith("-ext")) {
                m = m.substring(0, m.length() - 4);
            } else if (m.endsWith("-debug")) {
                m = m.substring(0, m.length() - 6);
            } else {
                return m;
            }
        }
    }

    @Override
    public String toString() {
        return artifactId + " [" + line.label() + " / " + module + "]";
    }
}
