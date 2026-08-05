package io.mikko.bccheck;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileOutputStream;
import java.io.PrintStream;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/**
 * 命令行入口。
 *
 * <pre>
 *   java -jar bc-check.jar &lt;路径&gt; [更多路径...] [选项]
 *   java -jar bc-check.jar --gav bcprov-jdk18on:1.81
 * </pre>
 *
 * <p>退出码：0 = 未发现需处理项；1 = 命中 CVE；2 = 用法错误。
 */
public final class Main {

    static final String VERSION = "0.1.0";

    private static final int EXIT_OK = 0;
    private static final int EXIT_FOUND = 1;
    private static final int EXIT_USAGE = 2;

    /**
     * 全部输出走这里，以便控制字符编码。
     *
     * <p>Windows 上 Java 拿不到控制台的真实代码页，{@code file.encoding} 与 {@code chcp}
     * 常常对不上，中文就会变成乱码。默认沿用平台编码，乱码时用 {@code --utf8} / {@code --gbk} 指定。
     */
    private static PrintStream out = System.out;

    public static void main(String[] args) {
        List<String> targets = new ArrayList<String>();
        List<String> gavs = new ArrayList<String>();
        boolean json = false;
        boolean detail = false;
        boolean color = System.console() != null;
        String encoding = null;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if ("--help".equals(arg) || "-h".equals(arg)) {
                printUsage();
                System.exit(EXIT_OK);
            } else if ("--version".equals(arg) || "-v".equals(arg)) {
                out.println("bc-check " + VERSION);
                System.exit(EXIT_OK);
            } else if ("--gav".equals(arg)) {
                if (i + 1 >= args.length) {
                    System.err.println("--gav 后面要跟坐标，如 bcprov-jdk18on:1.81");
                    System.exit(EXIT_USAGE);
                }
                gavs.add(args[++i]);
            } else if ("--json".equals(arg)) {
                json = true;
            } else if ("--detail".equals(arg) || "-d".equals(arg)) {
                detail = true;
            } else if ("--utf8".equals(arg)) {
                encoding = "UTF-8";
            } else if ("--gbk".equals(arg)) {
                encoding = "GBK";
            } else if ("--no-color".equals(arg)) {
                color = false;
            } else if ("--color".equals(arg)) {
                color = true;
            } else if (arg.startsWith("-")) {
                System.err.println("未知选项：" + arg);
                printUsage();
                System.exit(EXIT_USAGE);
            } else {
                targets.add(arg);
            }
        }

        if (targets.isEmpty() && gavs.isEmpty()) {
            printUsage();
            System.exit(EXIT_USAGE);
        }

        // JSON 恒用 UTF-8：JSON 标准要求如此，且多为管道消费，与控制台编码无关
        out = createOut(json ? "UTF-8" : encoding);

        JarScanner scanner = new JarScanner();
        for (String t : targets) {
            scanner.scan(new File(t));
        }

        List<Detection> found = new ArrayList<Detection>(scanner.detections());
        for (String gav : gavs) {
            Detection d = fromGav(gav, scanner);
            if (d != null) {
                found.add(d);
            }
        }

        Collections.sort(found, new Comparator<Detection>() {
            public int compare(Detection a, Detection b) {
                return a.severity().ordinal() - b.severity().ordinal();
            }
        });

        if (json) {
            out.println(Report.toJson(VERSION, targets, gavs, scanner, found));
        } else {
            Report.print(out, VERSION, targets, gavs, scanner, found, color, detail);
        }

        for (Detection d : found) {
            if (d.severity().isActionable()) {
                System.exit(EXIT_FOUND);
            }
        }
        System.exit(EXIT_OK);
    }

    /**
     * 解析 {@code --gav} 参数：允许 {@code groupId:artifactId:version} 或 {@code artifactId:version}。
     *
     * @return 无法解析时返回 null，并把原因写进 warnings
     */
    static Detection fromGav(String gav, JarScanner scanner) {
        String[] parts = gav.split(":");
        String artifactId;
        String version;
        if (parts.length == 3) {
            artifactId = parts[1];
            version = parts[2];
        } else if (parts.length == 2) {
            artifactId = parts[0];
            version = parts[1];
        } else {
            scanner.warnings().add("坐标格式不对，应为 artifactId:version 或 groupId:artifactId:version：" + gav);
            return null;
        }

        Coordinate c = Coordinate.of(artifactId);
        if (c == null) {
            scanner.warnings().add("认不出这是哪条产品线的 Bouncy Castle 构件：" + artifactId
                    + "（常规版形如 bcprov-jdk18on，LTS 版形如 bcprov-lts8on，FIPS 版形如 bc-fips）");
            return null;
        }
        return new Detection("（命令行指定）", artifactId, version, Detection.Source.COMMAND_LINE,
                false, false, Judge.assess(c, version));
    }

    private static void printUsage() {
        out.println();
        out.println("bc-check " + VERSION);
        out.println("查出你的 jar 里有没有 Bouncy Castle、属于哪条产品线、命中 2026 年这批 CVE 的哪几条。");
        out.println();
        out.println("用法：");
        out.println("  java -jar bc-check.jar <路径> [更多路径...] [选项]");
        out.println("  java -jar bc-check.jar --gav bcprov-jdk18on:1.81");
        out.println();
        out.println("路径可以是：");
        out.println("  - 一个 jar / war 文件（含 Spring Boot fat-JAR，会自动逐层展开）");
        out.println("  - 一个目录（递归查找其中所有 jar/war）");
        out.println();
        out.println("选项：");
        out.println("  --gav <坐标>   不扫文件，直接判定一个坐标，如 bcprov-lts8on:2.73.5");
        out.println("  -d, --detail  逐条列出命中的 CVE 与官方原文");
        out.println("  --json        输出 JSON，便于接入流水线（恒为 UTF-8）");
        out.println("  --utf8        强制以 UTF-8 输出（控制台中文乱码时用）");
        out.println("  --gbk         强制以 GBK 输出（控制台中文乱码时用）");
        out.println("  --no-color    关闭彩色输出");
        out.println("  -h, --help    显示本帮助");
        out.println("  -v, --version 显示版本");
        out.println();
        out.println("退出码：0 = 未命中；1 = 命中 CVE；2 = 用法错误");
        out.println();
        out.println("示例：");
        out.println("  java -jar bc-check.jar ./app.jar");
        out.println("  java -jar bc-check.jar /opt/apps --json");
        out.println("  java -jar bc-check.jar --gav bc-fips:1.0.2.5 --detail");
        out.println();
        out.println("本工具完全离线运行，不联网、不上传任何数据。");
        out.println();
    }

    /** 按指定编码创建标准输出流；传 null 表示沿用平台默认。 */
    private static PrintStream createOut(String encoding) {
        String enc = encoding;
        if (enc == null) {
            enc = System.getProperty("file.encoding");
        }
        if (enc == null) {
            return System.out;
        }
        try {
            return new PrintStream(new FileOutputStream(FileDescriptor.out), true, enc);
        } catch (UnsupportedEncodingException e) {
            // 编码不被支持时退回默认输出，不因为编码问题让工具跑不起来
            return System.out;
        }
    }

    /** 汇总一批判定里出现过的「大概率属于别的模块」的模块名，用于降噪提示。 */
    static Set<String> otherModules(Judge.Assessment a) {
        Set<String> s = new LinkedHashSet<String>();
        for (Judge.Hit h : a.hits) {
            if (h.otherModuleLikely) {
                s.addAll(h.rule.modules);
            }
        }
        return s;
    }

    private Main() {
    }
}
