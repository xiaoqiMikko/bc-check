package io.mikko.bccheck;

import java.io.PrintStream;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/** 报告输出：控制台与 JSON 两种形态。 */
final class Report {

    private Report() {
    }

    // ---------------- 控制台 ----------------

    static void print(PrintStream out, String toolVersion, List<String> targets, List<String> gavs,
                      JarScanner scanner, List<Detection> found, boolean color, boolean detail) {
        out.println();
        out.println("bc-check " + toolVersion + "  —— Bouncy Castle 2026 年 CVE 排查（离线，不外传任何数据）");
        out.println();
        if (!targets.isEmpty()) {
            out.println("扫描目标：" + join(targets, "、"));
            out.println("已展开归档：" + scanner.scannedArchives() + " 个");
        }
        if (!gavs.isEmpty()) {
            out.println("指定坐标：" + join(gavs, "、"));
        }
        out.println();

        if (found.isEmpty()) {
            out.println(paint("未发现 Bouncy Castle。", Ansi.GREEN, color));
            out.println();
            out.println("说明：本工具通过 META-INF/maven/org.bouncycastle/ 元数据与 org/bouncycastle/ class 判定，");
            out.println("      若依赖被改包名重打包（relocate），可能无法识别。");
            printWarnings(out, scanner);
            return;
        }

        out.println("发现 " + found.size() + " 处 Bouncy Castle：");
        out.println();

        for (Detection d : found) {
            printOne(out, d, color, detail);
        }

        Map<Severity, Integer> counts = new LinkedHashMap<Severity, Integer>();
        for (Severity s : Severity.values()) {
            counts.put(s, 0);
        }
        for (Detection d : found) {
            counts.put(d.severity(), counts.get(d.severity()) + 1);
        }
        StringBuilder summary = new StringBuilder("汇总：");
        for (Map.Entry<Severity, Integer> e : counts.entrySet()) {
            if (e.getValue() > 0) {
                summary.append(e.getKey().label()).append(' ').append(e.getValue()).append("　");
            }
        }
        out.println(summary.toString().trim());
        printWarnings(out, scanner);
    }

    private static void printOne(PrintStream out, Detection d, boolean color, boolean detail) {
        Severity sev = d.severity();
        String head = paint("[" + sev.label() + "]", colorOf(sev), color) + " "
                + (d.artifactId != null ? d.artifactId : "（认不出坐标）")
                + " " + (d.version != null ? d.version : "版本未知");
        if (d.assessment != null) {
            head += "　" + d.assessment.coordinate.line.label() + " 线";
        }
        out.println(head);
        out.println("  位置　　：" + d.location);
        out.println("  来源　　：" + d.source.label());

        if (d.springBootFatJar) {
            out.println("  场景　　：Spring Boot fat-JAR"
                    + paint("  ← 依赖被打进包里，pom 里往往看不到它", Ansi.YELLOW, color));
        }
        if (d.shaded) {
            out.println("  " + paint("注意　　：有 org/bouncycastle/ 的 class 但没有 Maven 元数据，"
                    + "疑似被 shade 进宿主 jar —— mvn dependency:tree 和 SCA 都查不到它", Ansi.YELLOW, color));
        }

        if (d.assessment == null) {
            out.println("  结论　　：认不出产品线，无法判定");
            out.println("  处置　　：手动确认这段 BC 代码来自哪个 artifact 与版本。"
                    + "常规版形如 bcprov-jdk18on，LTS 版形如 bcprov-lts8on，FIPS 版形如 bc-fips，"
                    + "三条线的版本号体系完全不同，不能拿「1.85」互相比对。");
            out.println();
            return;
        }

        Judge.Assessment a = d.assessment;
        if (a.versionUnknown) {
            out.println("  结论　　：版本号取不到或解析不了，无法判定");
            out.println("  处置　　：手动确认版本后，用 --gav " + d.artifactId + ":<版本> 再判一次。");
            out.println();
            return;
        }

        if (a.hits.isEmpty()) {
            out.println("  结论　　：" + paint("不受 2026 年这批 CVE 影响", Ansi.GREEN, color));
            out.println();
            return;
        }

        String hitLine = "命中 " + a.hits.size() + " 条 CVE";
        if (a.criticalCount() > 0) {
            hitLine += "，其中 CVSS critical " + paint(a.criticalCount() + " 条", Ansi.RED, color);
        }
        out.println("  结论　　：" + hitLine);

        Set<String> others = Main.otherModules(a);
        if (!others.isEmpty()) {
            int n = a.hits.size() - a.relevantCount();
            out.println("  降噪　　：其中 " + n + " 条按官方 FIPS 侧点名的 artifact 反推，大概率出在 "
                    + join(new java.util.ArrayList<String>(others), " / ") + " 模块。");
            out.println("            ⚠️ 这是推断不是官方结论 —— 官方对非 FIPS 线只写「before 1.85」，"
                    + "不指明 artifact，所以仅供排优先级，不能据此认定你不受影响。");
        }

        if (a.fixVersion != null) {
            out.println("  处置　　：升级到 " + paint(a.fixVersion, Ansi.GREEN, color)
                    + "（" + a.coordinate.line.label() + " 线）");
        } else {
            out.println("  处置　　：见下方各条 CVE 的官方 Fixed versions。");
        }

        if (detail) {
            out.println("  明细　　：");
            for (Judge.Hit h : a.hits) {
                out.println("    " + (h.rule.critical ? paint("● ", Ansi.RED, color) : "○ ")
                        + h.rule.cve + (h.otherModuleLikely ? "（大概率属其他模块）" : ""));
                out.println("      " + h.rule.title);
                out.println("      官方受影响：" + h.rule.affecting);
                out.println("      官方修复版：" + h.rule.fixed);
            }
        } else {
            out.println("  明细　　：加 --detail 看逐条 CVE 与官方原文");
        }
        out.println();
    }

    private static void printWarnings(PrintStream out, JarScanner scanner) {
        if (scanner.warnings().isEmpty()) {
            return;
        }
        out.println();
        out.println("扫描过程中的提示：");
        for (String w : scanner.warnings()) {
            out.println("  - " + w);
        }
    }

    // ---------------- JSON ----------------

    /** 手写 JSON，刻意不引入任何 JSON 库 —— 排查工具不该再往目标环境里塞依赖。 */
    static String toJson(String toolVersion, List<String> targets, List<String> gavs,
                         JarScanner scanner, List<Detection> found) {
        StringBuilder sb = new StringBuilder();
        sb.append("{\n");
        sb.append("  \"tool\": \"bc-check\",\n");
        sb.append("  \"version\": \"").append(esc(toolVersion)).append("\",\n");
        sb.append("  \"scannedArchives\": ").append(scanner.scannedArchives()).append(",\n");
        sb.append("  \"targets\": ").append(arr(targets)).append(",\n");
        sb.append("  \"gav\": ").append(arr(gavs)).append(",\n");

        sb.append("  \"findings\": [\n");
        for (int i = 0; i < found.size(); i++) {
            Detection d = found.get(i);
            Judge.Assessment a = d.assessment;
            sb.append("    {\n");
            sb.append("      \"severity\": \"").append(esc(d.severity().label())).append("\",\n");
            sb.append("      \"artifactId\": ").append(str(d.artifactId)).append(",\n");
            sb.append("      \"version\": ").append(str(d.version)).append(",\n");
            sb.append("      \"line\": ").append(str(a == null ? null : a.coordinate.line.name())).append(",\n");
            sb.append("      \"module\": ").append(str(a == null ? null : a.coordinate.module)).append(",\n");
            sb.append("      \"location\": ").append(str(d.location)).append(",\n");
            sb.append("      \"source\": \"").append(esc(d.source.name())).append("\",\n");
            sb.append("      \"springBootFatJar\": ").append(d.springBootFatJar).append(",\n");
            sb.append("      \"shaded\": ").append(d.shaded).append(",\n");
            sb.append("      \"fixVersion\": ").append(str(a == null ? null : a.fixVersion)).append(",\n");
            sb.append("      \"cves\": [");
            if (a != null) {
                for (int j = 0; j < a.hits.size(); j++) {
                    Judge.Hit h = a.hits.get(j);
                    sb.append(j > 0 ? ",\n        " : "\n        ");
                    sb.append("{\"id\": \"").append(esc(h.rule.cve)).append("\"");
                    sb.append(", \"critical\": ").append(h.rule.critical);
                    sb.append(", \"otherModuleLikely\": ").append(h.otherModuleLikely);
                    sb.append(", \"title\": \"").append(esc(h.rule.title)).append("\"");
                    sb.append(", \"affecting\": \"").append(esc(h.rule.affecting)).append("\"");
                    sb.append(", \"fixed\": \"").append(esc(h.rule.fixed)).append("\"}");
                }
                if (!a.hits.isEmpty()) {
                    sb.append("\n      ");
                }
            }
            sb.append("]\n");
            sb.append("    }").append(i < found.size() - 1 ? "," : "").append("\n");
        }
        sb.append("  ],\n");
        sb.append("  \"warnings\": ").append(arr(scanner.warnings())).append("\n");
        sb.append("}");
        return sb.toString();
    }

    private static String arr(List<String> items) {
        StringBuilder sb = new StringBuilder("[");
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) {
                sb.append(", ");
            }
            sb.append('"').append(esc(items.get(i))).append('"');
        }
        return sb.append(']').toString();
    }

    private static String str(String s) {
        return s == null ? "null" : "\"" + esc(s) + "\"";
    }

    static String esc(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"':  sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n");  break;
                case '\r': sb.append("\\r");  break;
                case '\t': sb.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    // ---------------- 杂项 ----------------

    private static String colorOf(Severity s) {
        switch (s) {
            case CRITICAL: return Ansi.RED;
            case HIGH:     return Ansi.YELLOW;
            case UNKNOWN:  return Ansi.YELLOW;
            case OK:       return Ansi.GREEN;
            default:       return Ansi.RESET;
        }
    }

    private static String paint(String text, String color, boolean enabled) {
        return enabled ? color + text + Ansi.RESET : text;
    }

    private static String join(List<String> items, String sep) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < items.size(); i++) {
            if (i > 0) {
                sb.append(sep);
            }
            sb.append(items.get(i));
        }
        return sb.toString();
    }

    /** ANSI 颜色码。 */
    private static final class Ansi {
        static final String RESET = "\u001B[0m";
        static final String RED = "\u001B[31m";
        static final String GREEN = "\u001B[32m";
        static final String YELLOW = "\u001B[33m";
    }
}
