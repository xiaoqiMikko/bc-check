package io.mikko.bccheck;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

/**
 * 在 jar / war / 目录里找出所有 Bouncy Castle 构件。
 *
 * <p>关键能力是<b>递归进入嵌套 jar</b>：Spring Boot fat-JAR 把依赖全塞进 {@code BOOT-INF/lib/}，
 * 而 BC 绝大多数情况是被传递依赖拖进来的（TLS / 证书 / JWT / PDF 签名 / PGP 都会引它），
 * 项目自己的 pom 里往往根本没写。本扫描器在内存里逐层展开，不解压、不落地、不联网。
 */
public class JarScanner {

    /** BC 的 Maven 元数据路径，groupId 恒为 org.bouncycastle（含 FIPS 版）。 */
    private static final Pattern POM_PROPS =
            Pattern.compile("^META-INF/maven/org\\.bouncycastle/([^/]+)/pom\\.properties$");

    /** 从 jar 文件名提取坐标，如 bcprov-jdk18on-1.81.jar、bc-fips-1.0.2.5.jar。 */
    private static final Pattern JAR_NAME =
            Pattern.compile("^(bc[A-Za-z0-9]*(?:-(?:ext|debug))?(?:-(?:jdk[A-Za-z0-9]+|lts[A-Za-z0-9]+|fips))?)"
                    + "-(\\d[\\w.]*?)\\.jar$");

    /** BC 代码的标志性 class，用于识别被 shade 进宿主 jar 的情况。 */
    private static final String MARKER = "org/bouncycastle/";

    /** multi-release jar 把高版本 class 放这儿，BC 官方 jar 全是 multi-release。 */
    private static final Pattern MARKER_MR =
            Pattern.compile("^META-INF/versions/\\d+/org/bouncycastle/.+\\.class$");

    private static final String MANIFEST = "META-INF/MANIFEST.MF";

    /** 嵌套条目读取上限，防畸形包撑爆内存。 */
    private static final long MAX_NESTED_ENTRY_BYTES = 64L * 1024 * 1024;

    /** 递归深度上限，防 zip 套娃。 */
    private static final int MAX_DEPTH = 8;

    private final List<Detection> detections = new ArrayList<Detection>();
    private final List<String> warnings = new ArrayList<String>();
    private int scannedArchives;

    public List<Detection> detections() {
        return detections;
    }

    public List<String> warnings() {
        return warnings;
    }

    public int scannedArchives() {
        return scannedArchives;
    }

    /** 扫描一个路径：jar/war/ear 文件，或递归扫一个目录。 */
    public void scan(File target) {
        if (!target.exists()) {
            warnings.add("路径不存在：" + target.getPath());
            return;
        }
        if (target.isDirectory()) {
            scanDirectory(target);
        } else if (isArchive(target.getName())) {
            scanArchiveFile(target);
        } else {
            warnings.add("跳过（不是 jar/war/ear）：" + target.getPath());
        }
    }

    private void scanDirectory(File dir) {
        File[] children = dir.listFiles();
        if (children == null) {
            warnings.add("目录无法读取：" + dir.getPath());
            return;
        }
        for (File child : children) {
            if (child.isDirectory()) {
                scanDirectory(child);
            } else if (isArchive(child.getName())) {
                scanArchiveFile(child);
            }
        }
    }

    private void scanArchiveFile(File file) {
        InputStream in = null;
        try {
            in = new FileInputStream(file);
            scanArchiveStream(in, file.getPath(), file.getName(), 0, false);
        } catch (IOException e) {
            warnings.add("读取失败 " + file.getPath() + "：" + e.getMessage());
        } finally {
            closeQuietly(in);
        }
    }

    /**
     * 扫描一个归档流。
     *
     * @param location    展示用逻辑路径
     * @param archiveName 当前归档文件名，用于从名字推坐标
     * @param inFatJar    外层是否 Spring Boot fat-JAR；必须向下传递，
     *                    因为 {@code BOOT-INF/lib/} 里的依赖 jar 自身并不含 BOOT-INF 目录
     */
    private void scanArchiveStream(InputStream in, String location, String archiveName, int depth,
                                   boolean inFatJar) throws IOException {
        if (depth > MAX_DEPTH) {
            warnings.add("嵌套层级超过上限，已停止深入：" + location);
            return;
        }
        scannedArchives++;

        // 一个归档里可能同时躺着多个 BC 构件（uber-jar 常见），所以用 map 收集
        Map<String, String> fromPom = new LinkedHashMap<String, String>();
        String[] fromManifest = null;
        boolean hasBcClass = false;
        boolean springBootFatJar = false;
        List<NestedArchive> nested = new ArrayList<NestedArchive>();

        ZipInputStream zis = new ZipInputStream(in);
        ZipEntry entry;
        while ((entry = zis.getNextEntry()) != null) {
            String name = entry.getName();

            if (name.startsWith("BOOT-INF/")) {
                springBootFatJar = true;
            }
            if ((name.startsWith(MARKER) && name.endsWith(".class")) || MARKER_MR.matcher(name).matches()) {
                hasBcClass = true;
                continue;
            }
            if (MANIFEST.equals(name)) {
                fromManifest = readManifest(zis);
                continue;
            }

            Matcher m = POM_PROPS.matcher(name);
            if (m.matches()) {
                String version = readVersion(zis);
                if (version != null) {
                    fromPom.put(m.group(1), version);
                }
            } else if (!entry.isDirectory() && isArchive(name)) {
                long size = entry.getSize();
                if (size > MAX_NESTED_ENTRY_BYTES) {
                    warnings.add("嵌套包过大已跳过（" + size + " 字节）：" + location + "!/" + name);
                    continue;
                }
                byte[] bytes = readAllBytes(zis, MAX_NESTED_ENTRY_BYTES);
                if (bytes != null) {
                    nested.add(new NestedArchive(name, bytes));
                }
            }
        }

        boolean fatJarContext = springBootFatJar || inFatJar;

        if (!fromPom.isEmpty()) {
            for (Map.Entry<String, String> e : fromPom.entrySet()) {
                record(location, e.getKey(), e.getValue(), Detection.Source.POM_PROPERTIES,
                        false, fatJarContext);
            }
        } else if (hasBcClass) {
            // 官方 jar 没有 Maven 元数据（BC 用 ant 打包），MANIFEST 才是主路径，
            // 而且它扛得住 jar 被改名 —— 内部制品库改名重发布很常见。
            String[] gav = fromManifest;
            Detection.Source source = Detection.Source.MANIFEST;
            if (gav == null || Coordinate.of(gav[0]) == null) {
                gav = fromFileName(archiveName);
                source = Detection.Source.FILE_NAME;
            } else {
                gav = preferFileNameArtifactId(gav, archiveName);
            }
            if (gav != null && Coordinate.of(gav[0]) != null) {
                record(location, gav[0], gav[1], source, false, fatJarContext);
            } else {
                // 认不出坐标 —— 被 shade 进宿主 jar 的典型形态，也是最难查的一种
                record(location, null, null, Detection.Source.CLASS_ONLY, true, fatJarContext);
            }
        }

        for (NestedArchive na : nested) {
            String childLocation = location + "!/" + na.entryName;
            String childName = na.entryName.substring(na.entryName.lastIndexOf('/') + 1);
            try {
                scanArchiveStream(new ByteArrayInputStream(na.content), childLocation, childName,
                        depth + 1, fatJarContext);
            } catch (IOException e) {
                warnings.add("嵌套包读取失败 " + childLocation + "：" + e.getMessage());
            }
        }
    }

    private void record(String location, String artifactId, String version, Detection.Source source,
                        boolean shaded, boolean springBootFatJar) {
        Coordinate c = Coordinate.of(artifactId);
        Judge.Assessment a = c == null ? null : Judge.assess(c, version);
        detections.add(new Detection(location, artifactId, version, source, shaded,
                springBootFatJar, a));
    }

    /**
     * MANIFEST 与文件名一致时，展示用文件名里那个更具体的 artifactId。
     *
     * <p>BC 线的 {@code Bundle-SymbolicName} 是裸模块名 {@code bcprov}，
     * 而用户要去 pom 里改的是 {@code bcprov-jdk18on} 还是 {@code bcprov-jdk15to18}。
     * 判定结果两者完全相同，但报告里给出可直接照抄的坐标，才省得用户再查一次。
     * 版本仍以 MANIFEST 为准 —— 文件名可以被随意改，MANIFEST 是打包时写进去的。
     */
    private static String[] preferFileNameArtifactId(String[] fromManifest, String archiveName) {
        String[] byName = fromFileName(archiveName);
        if (byName == null) {
            return fromManifest;
        }
        Coordinate cm = Coordinate.of(fromManifest[0]);
        Coordinate cn = Coordinate.of(byName[0]);
        if (cm != null && cn != null && cm.line == cn.line && cm.module.equals(cn.module)) {
            return new String[]{byName[0], fromManifest[1]};
        }
        return fromManifest;
    }

    /** 从 jar 文件名解析出 {artifactId, version}；认不出返回 null。 */
    static String[] fromFileName(String jarName) {
        if (jarName == null) {
            return null;
        }
        Matcher m = JAR_NAME.matcher(jarName);
        return m.matches() ? new String[]{m.group(1), m.group(2)} : null;
    }

    /**
     * 从 MANIFEST 读出 {artifactId, version}。
     *
     * <p>官方 jar 的实测形态：
     * <pre>
     *   bcprov-jdk18on-1.81  -> Bundle-SymbolicName: bcprov          Bundle-Version: 1.81
     *   bcprov-lts8on-2.73.5 -> Bundle-SymbolicName: bcprov-lts8on   Bundle-Version: 2.73.5
     *   bc-fips-1.0.2.5      -> Bundle-SymbolicName: bc-fips         Bundle-Version: 1.0.2.5
     * </pre>
     * LTS 与 FIPS 的 SymbolicName 自带产品线后缀，BC 线则是裸模块名 —— 三条线因此可分辨。
     *
     * <p>⚠️ <b>只读第一个空行之前的主属性段。</b>官方 BC jar 是签名过的，
     * MANIFEST 里跟着每个 class 一段摘要 —— bcprov 有 6000 多个条目，整份 MANIFEST 上兆，
     * 一次性读进来既浪费又会撞上读取上限（真实构件复验时就是这么把识别整条打掉的，
     * 而仿真出来的小 jar 永远碰不到这个问题）。
     *
     * @return 认不出时返回 null
     */
    static String[] readManifest(InputStream in) {
        StringBuilder head = new StringBuilder();
        try {
            byte[] buf = new byte[4096];
            int n;
            while (head.length() < 64 * 1024 && (n = in.read(buf)) > 0) {
                head.append(new String(buf, 0, n, "UTF-8"));
                // 空行标志主属性段结束，后面全是每个文件的签名摘要，与我们无关
                if (head.indexOf("\n\n") >= 0 || head.indexOf("\r\n\r\n") >= 0) {
                    break;
                }
            }
        } catch (IOException e) {
            return null;
        }

        String name = null;
        String bundleVersion = null;
        String implVersion = null;
        for (String line : head.toString().split("\r\n|\n|\r")) {
            if (line.isEmpty()) {
                break;
            }
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            String key = line.substring(0, colon).trim();
            String value = line.substring(colon + 1).trim();
            if ("Bundle-SymbolicName".equalsIgnoreCase(key)) {
                // OSGi 允许带指令后缀，如 "bcprov;singleton:=true"
                int semi = value.indexOf(';');
                name = trimOrNull(semi > 0 ? value.substring(0, semi) : value);
            } else if ("Bundle-Version".equalsIgnoreCase(key)) {
                bundleVersion = trimOrNull(value);
            } else if ("Implementation-Version".equalsIgnoreCase(key)) {
                implVersion = trimOrNull(value);
            }
        }
        String version = bundleVersion != null ? bundleVersion : implVersion;
        return (name != null && version != null) ? new String[]{name, version} : null;
    }

    private static String trimOrNull(String s) {
        if (s == null) {
            return null;
        }
        String t = s.trim();
        return t.isEmpty() ? null : t;
    }

    private static String readVersion(InputStream in) {
        byte[] bytes = readAllBytes(in, 64 * 1024);
        if (bytes == null) {
            return null;
        }
        Properties props = new Properties();
        try {
            props.load(new ByteArrayInputStream(bytes));
        } catch (IOException e) {
            return null;
        }
        String v = props.getProperty("version");
        return (v != null && !v.trim().isEmpty()) ? v.trim() : null;
    }

    static boolean isArchive(String name) {
        if (name == null) {
            return false;
        }
        String lower = name.toLowerCase();
        return lower.endsWith(".jar") || lower.endsWith(".war") || lower.endsWith(".ear");
    }

    /** 读满整个流；超过上限则放弃并返回 null。 */
    private static byte[] readAllBytes(InputStream in, long limit) {
        try {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[8192];
            long total = 0;
            int n;
            while ((n = in.read(buf)) > 0) {
                total += n;
                if (total > limit) {
                    return null;
                }
                out.write(buf, 0, n);
            }
            return out.toByteArray();
        } catch (IOException e) {
            return null;
        }
    }

    private static void closeQuietly(InputStream in) {
        if (in != null) {
            try {
                in.close();
            } catch (IOException ignored) {
                // 关闭失败不影响结果
            }
        }
    }

    /** 暂存待深入扫描的嵌套归档 —— 同一个 ZipInputStream 不能边遍历边递归读。 */
    private static final class NestedArchive {
        final String entryName;
        final byte[] content;

        NestedArchive(String entryName, byte[] content) {
            this.entryName = entryName;
            this.content = content;
        }
    }
}
