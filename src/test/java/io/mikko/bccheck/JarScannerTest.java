package io.mikko.bccheck;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

/**
 * 扫描器的端到端测试。
 *
 * <p>⚠️ 这里造的是仿真 jar，只能验证嵌套展开与识别顺序这类结构逻辑。
 * <b>仿真包测不出真 bug</b> —— 真实构件复验的结论记在 README 与 {@code docs/bets/4-bouncycastle.md}：
 * 官方 jar 没有 Maven 元数据、且签名 MANIFEST 长达上兆，这两点都是仿真包碰不到的。
 */
public class JarScannerTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    /** 造一个含 BC class 的 jar，可选写入 MANIFEST 主属性。 */
    private static byte[] bcJar(String symbolicName, String bundleVersion) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ZipOutputStream zos = new ZipOutputStream(bos);
        if (symbolicName != null) {
            StringBuilder mf = new StringBuilder("Manifest-Version: 1.0\r\n");
            mf.append("Bundle-SymbolicName: ").append(symbolicName).append("\r\n");
            if (bundleVersion != null) {
                mf.append("Bundle-Version: ").append(bundleVersion).append("\r\n");
            }
            mf.append("\r\n");
            // 模拟签名 jar：主属性段之后跟着大量摘要块，解析必须在第一个空行处停下
            for (int i = 0; i < 2000; i++) {
                mf.append("Name: org/bouncycastle/filler").append(i).append(".class\r\n");
                mf.append("SHA-256-Digest: 0000000000000000000000000000000000000000000=\r\n\r\n");
            }
            write(zos, "META-INF/MANIFEST.MF", mf.toString().getBytes("UTF-8"));
        }
        write(zos, "org/bouncycastle/jce/provider/BouncyCastleProvider.class", new byte[]{1, 2, 3});
        zos.close();
        return bos.toByteArray();
    }

    private static void write(ZipOutputStream zos, String name, byte[] content) throws IOException {
        zos.putNextEntry(new ZipEntry(name));
        zos.write(content);
        zos.closeEntry();
    }

    /** 造一个 Spring Boot fat-JAR，把若干依赖塞进 BOOT-INF/lib/。 */
    private File fatJar(String fileName, Map<String, byte[]> libs) throws IOException {
        File f = tmp.newFile(fileName);
        OutputStream fos = new FileOutputStream(f);
        ZipOutputStream zos = new ZipOutputStream(fos);
        write(zos, "BOOT-INF/classes/com/example/App.class", new byte[]{9});
        for (Map.Entry<String, byte[]> e : libs.entrySet()) {
            write(zos, "BOOT-INF/lib/" + e.getKey(), e.getValue());
        }
        zos.close();
        fos.close();
        return f;
    }

    @Test
    public void 从MANIFEST认出坐标并停在主属性段() throws Exception {
        String[] gav = JarScanner.readManifest(
                new java.io.ByteArrayInputStream(manifestOnly("bcprov", "1.81")));
        assertNotNull(gav);
        assertEquals("bcprov", gav[0]);
        assertEquals("1.81", gav[1]);
    }

    private static byte[] manifestOnly(String name, String version) throws IOException {
        StringBuilder mf = new StringBuilder("Manifest-Version: 1.0\r\n");
        mf.append("Bundle-SymbolicName: ").append(name).append("\r\n");
        mf.append("Bundle-Version: ").append(version).append("\r\n\r\n");
        for (int i = 0; i < 3000; i++) {
            mf.append("Name: org/bouncycastle/x").append(i).append(".class\r\n");
            mf.append("SHA-256-Digest: AAAA=\r\n\r\n");
        }
        return mf.toString().getBytes("UTF-8");
    }

    /** OSGi 允许 SymbolicName 带指令后缀。 */
    @Test
    public void 忽略SymbolicName的OSGi指令后缀() throws Exception {
        StringBuilder mf = new StringBuilder("Manifest-Version: 1.0\r\n");
        mf.append("Bundle-SymbolicName: bcprov;singleton:=true\r\n");
        mf.append("Bundle-Version: 1.81\r\n\r\n");
        String[] gav = JarScanner.readManifest(
                new java.io.ByteArrayInputStream(mf.toString().getBytes("UTF-8")));
        assertNotNull(gav);
        assertEquals("bcprov", gav[0]);
    }

    /** BC 绝大多数是被传递依赖拖进来的，只会出现在 fat-JAR 的 BOOT-INF/lib/ 里。 */
    @Test
    public void 逐层展开SpringBootFatJar() throws Exception {
        Map<String, byte[]> libs = new LinkedHashMap<String, byte[]>();
        libs.put("bcprov-jdk18on-1.81.jar", bcJar("bcprov", "1.81"));
        libs.put("bcprov-lts8on-2.73.5.jar", bcJar("bcprov-lts8on", "2.73.5"));
        libs.put("bc-fips-1.0.2.5.jar", bcJar("bc-fips", "1.0.2.5"));
        File app = fatJar("app.jar", libs);

        JarScanner scanner = new JarScanner();
        scanner.scan(app);
        assertEquals(3, scanner.detections().size());

        Map<String, Detection> byArtifact = new LinkedHashMap<String, Detection>();
        for (Detection d : scanner.detections()) {
            byArtifact.put(d.artifactId, d);
            assertTrue("应当标记为 fat-JAR 场景", d.springBootFatJar);
            assertTrue(d.location.contains("!/BOOT-INF/lib/"));
        }

        // 三条产品线各自判到自己的线上，修复版互不相同
        assertEquals(Coordinate.Line.BC, byArtifact.get("bcprov-jdk18on").assessment.coordinate.line);
        assertEquals("1.85", byArtifact.get("bcprov-jdk18on").assessment.fixVersion);
        assertEquals(Coordinate.Line.LTS, byArtifact.get("bcprov-lts8on").assessment.coordinate.line);
        assertEquals("2.73.12", byArtifact.get("bcprov-lts8on").assessment.fixVersion);
        assertEquals(Coordinate.Line.FIPS, byArtifact.get("bc-fips").assessment.coordinate.line);
        assertEquals("1.0.2.7", byArtifact.get("bc-fips").assessment.fixVersion);
    }

    /** jar 被改名后，文件名认不出，但 MANIFEST 还在。 */
    @Test
    public void jar改名后仍能认出() throws Exception {
        Map<String, byte[]> libs = new LinkedHashMap<String, byte[]>();
        libs.put("internal-crypto-lib.jar", bcJar("bcprov", "1.81"));
        File app = fatJar("renamed.jar", libs);

        JarScanner scanner = new JarScanner();
        scanner.scan(app);
        assertEquals(1, scanner.detections().size());
        Detection d = scanner.detections().get(0);
        assertEquals(Detection.Source.MANIFEST, d.source);
        assertEquals("bcprov", d.artifactId);
        assertEquals("1.81", d.version);
        assertEquals(Severity.CRITICAL, d.severity());
    }

    /** MANIFEST 给的是裸名时，展示用文件名里更具体的坐标，版本仍以 MANIFEST 为准。 */
    @Test
    public void 展示更具体的artifactId() throws Exception {
        Map<String, byte[]> libs = new LinkedHashMap<String, byte[]>();
        libs.put("bcprov-jdk15to18-1.81.jar", bcJar("bcprov", "1.81"));
        File app = fatJar("app2.jar", libs);

        JarScanner scanner = new JarScanner();
        scanner.scan(app);
        Detection d = scanner.detections().get(0);
        assertEquals("bcprov-jdk15to18", d.artifactId);
        assertEquals("1.81", d.version);
    }

    /** 有 BC 的 class 却认不出坐标 —— 被 shade 进宿主 jar，mvn dependency:tree 也看不见。 */
    @Test
    public void 认不出坐标时报UNKNOWN而不是漏报() throws Exception {
        File f = tmp.newFile("uber.jar");
        OutputStream fos = new FileOutputStream(f);
        ZipOutputStream zos = new ZipOutputStream(fos);
        write(zos, "org/bouncycastle/jce/provider/BouncyCastleProvider.class", new byte[]{1});
        write(zos, "com/example/App.class", new byte[]{2});
        zos.close();
        fos.close();

        JarScanner scanner = new JarScanner();
        scanner.scan(f);
        assertEquals(1, scanner.detections().size());
        Detection d = scanner.detections().get(0);
        assertTrue(d.shaded);
        assertNull(d.assessment);
        assertEquals(Severity.UNKNOWN, d.severity());
    }

    /** multi-release jar 把 class 放在 META-INF/versions/N/ 下，官方 BC jar 全是这种。 */
    @Test
    public void 识别multiRelease路径下的class() throws Exception {
        File f = tmp.newFile("mr.jar");
        OutputStream fos = new FileOutputStream(f);
        ZipOutputStream zos = new ZipOutputStream(fos);
        write(zos, "META-INF/versions/9/org/bouncycastle/tls/Foo.class", new byte[]{1});
        zos.close();
        fos.close();

        JarScanner scanner = new JarScanner();
        scanner.scan(f);
        assertEquals(1, scanner.detections().size());
    }

    @Test
    public void 没有BC的包不报() throws Exception {
        File f = tmp.newFile("plain.jar");
        OutputStream fos = new FileOutputStream(f);
        ZipOutputStream zos = new ZipOutputStream(fos);
        write(zos, "com/example/App.class", new byte[]{1});
        zos.close();
        fos.close();

        JarScanner scanner = new JarScanner();
        scanner.scan(f);
        assertTrue(scanner.detections().isEmpty());
    }
}
