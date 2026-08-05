package io.mikko.bccheck;

/** 一处被发现的 Bouncy Castle 构件。 */
public final class Detection {

    /** 版本与坐标是从哪儿认出来的 —— 直接决定判定可不可信。 */
    public enum Source {
        /**
         * {@code META-INF/maven/org.bouncycastle/<artifactId>/pom.properties}。
         *
         * <p>最权威，但官方 jar 里<b>没有</b>这个文件 —— Bouncy Castle 用 ant 打包，
         * 只有被 maven 二次打包/重发布的构件才带得上。
         */
        POM_PROPERTIES("Maven 元数据"),
        /**
         * {@code META-INF/MANIFEST.MF} 的 Bundle-SymbolicName + Bundle-Version。
         *
         * <p>官方 jar 的实际主路径，且 jar 被改名后依然认得出。
         */
        MANIFEST("jar 内 MANIFEST"),
        /** jar 文件名，如 {@code bcprov-jdk18on-1.81.jar}。 */
        FILE_NAME("jar 文件名"),
        /** 只在归档里找到了 {@code org/bouncycastle/} 的 class，认不出坐标。 */
        CLASS_ONLY("仅 class 特征"),
        /** 用 {@code --gav} 直接指定，没有扫任何文件。 */
        COMMAND_LINE("命令行指定");

        private final String label;

        Source(String label) {
            this.label = label;
        }

        public String label() {
            return label;
        }
    }

    /** 逻辑路径，嵌套时形如 {@code app.jar!/BOOT-INF/lib/bcprov-jdk18on-1.81.jar}。 */
    public final String location;
    /** 识别出的 artifactId；认不出时为 null。 */
    public final String artifactId;
    /** 识别出的版本；认不出时为 null。 */
    public final String version;
    public final Source source;
    /**
     * 有 BC 的 class 却没有对应的 Maven 元数据 —— 典型的被 shade 进宿主 jar。
     *
     * <p>这类最难查：{@code mvn dependency:tree} 看不见它，SCA 扫依赖清单也扫不到。
     */
    public final boolean shaded;
    /** 外层是 Spring Boot fat-JAR。 */
    public final boolean springBootFatJar;
    /** 判定结果；坐标认不出来时为 null。 */
    public final Judge.Assessment assessment;

    public Detection(String location, String artifactId, String version, Source source,
                     boolean shaded, boolean springBootFatJar, Judge.Assessment assessment) {
        this.location = location;
        this.artifactId = artifactId;
        this.version = version;
        this.source = source;
        this.shaded = shaded;
        this.springBootFatJar = springBootFatJar;
        this.assessment = assessment;
    }

    public Severity severity() {
        return assessment == null ? Severity.UNKNOWN : assessment.severity();
    }
}
