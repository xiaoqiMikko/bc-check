package io.mikko.bccheck;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Bouncy Castle CVE 判定表 —— <b>本文件由 tools/gen_rules.py 自动生成，不要手改</b>。
 *
 * <p>数据源：{@code tools/data/bc_cves.json}，逐条抓自官方
 * {@code github.com/bcgit/bc-java/wiki} 的 CVE 子页面（一手，非二手转述）。
 * 重新生成：{@code python tools/gen_rules.py}。
 *
 * <p>为什么不能照「Bouncy Castle for Java before 1.85」一刀切判定：
 * <ul>
 *   <li>BC-LTS 用户的版本号是 {@code 2.73.x}、FIPS 用户是 {@code 1.0.x / 2.0.x / 2.1.x}，
 *       拿「before 1.85」去比对，三条产品线里有两条完全无从判断。</li>
 *   <li>有 CVE 只影响单一产品线：{@code CVE-2026-8149} 压根不影响 BC，只影响 BC-LTS。</li>
 *   <li>FIPS 侧逐条不同：同一批漏洞里，有的要查 {@code bc-fips}，
 *       有的要查 {@code bctls-fips}，还有的 FIPS 根本不受影响。</li>
 *   <li>10 条 CVE 有起始受影响版本，不是「全版本受影响」。</li>
 * </ul>
 */
public final class CveTable {

    /** 一段版本区间。{@code from} 为 null 表示不限下界（即「before X」型）。 */
    public static final class V {
        public final String from;
        public final String upper;

        V(String from, String upper) {
            this.from = from;
            this.upper = upper;
        }
    }

    /** 某个 FIPS artifact 的受影响规则。 */
    public static final class F {
        /**
         * true = 「before X」型：各版本线小于 X 即受影响，<b>且未被列出的版本线不受影响</b>。
         * false = 闭区间型（上界含），官方只对 CVE-2026-5588 用了这种写法。
         */
        public final boolean before;
        public final V[] lines;

        F(boolean before, V[] lines) {
            this.before = before;
            this.lines = lines;
        }
    }

    /** 一条 CVE 的完整判定规则。 */
    public static final class Rule {
        public final String cve;
        public final String title;
        public final boolean critical;
        /** 官方 Issue affecting 原文，报告里原样引用，避免转述走样。 */
        public final String affecting;
        /** 官方 Fixed versions 原文。 */
        public final String fixed;
        /** BC 线（jdk18on / jdk15to18 等）受影响区间；空数组表示不影响 BC 线。 */
        public final V[] bc;
        /** BC 线区间是否为「before」型（上界不含）。false 表示闭区间（上界含）。 */
        public final boolean bcBefore;
        /** BC-LTS 线受影响区间。 */
        public final V[] lts;
        public final boolean ltsBefore;
        /** 仅当该 CVE 只影响 LTS 线的某个模块时非 null（目前只有 CVE-2026-5588 的 bcpkix）。 */
        public final String ltsModule;
        /** FIPS：artifact -> 该 artifact 各版本线的受影响区间。 */
        public final Map<String, F> fips;
        /** 按 FIPS 侧 artifact 反推的相关模块，<b>推断值</b>，仅用于降噪提示。 */
        public final List<String> modules;

        Rule(String cve, String title, boolean critical, String affecting, String fixed,
             V[] bc, boolean bcBefore, V[] lts, boolean ltsBefore, String ltsModule,
             Map<String, F> fips, String[] modules) {
            this.cve = cve;
            this.title = title;
            this.critical = critical;
            this.affecting = affecting;
            this.fixed = fixed;
            this.bc = bc;
            this.bcBefore = bcBefore;
            this.lts = lts;
            this.ltsBefore = ltsBefore;
            this.ltsModule = ltsModule;
            this.fips = fips;
            this.modules = Collections.unmodifiableList(Arrays.asList(modules));
        }
    }

    private static final List<Rule> RULES = new ArrayList<Rule>();

    /** 全部 37 条规则，顺序与官方 wiki 一致。 */
    public static List<Rule> rules() {
        return Collections.unmodifiableList(RULES);
    }

    private static Map<String, F> fips(Object... kv) {
        Map<String, F> m = new LinkedHashMap<String, F>();
        for (int i = 0; i < kv.length; i += 2) {
            m.put((String) kv[i], (F) kv[i + 1]);
        }
        return m;
    }

    static {
        RULES.add(new Rule("CVE-2026-0636", "LDAP Injection Vulnerability in LDAPStoreHelper.java", false,
                "BC 1.74 to 1.80.1, BC 1.81, BC 1.82 to BC 1.83",
                "BC 1.80.2, BC 1.81.1, BC 1.84",
                new V[]{new V("1.74", "1.80.1"), new V("1.81", "1.81"), new V("1.82", "1.83")}, false,
                new V[]{}, false, null,
                fips(),
                new String[]{}));
        RULES.add(new Rule("CVE-2026-12185", "BKS/UBER keystore allocates from untrusted lengths before integrity check", false,
                "BC before 1.85, BC-LTS before 2.73.12",
                "BC 1.85, BC-LTS 2.73.12",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips(),
                new String[]{}));
        RULES.add(new Rule("CVE-2026-12802", "CMS AuthEnvelopedData fails to enforce tag-length on decryption", false,
                "BC before 1.85, BC-LTS before 2.73.12, BC-FJA before bcpkix-fips 1.0.12, 2.0.12 and 2.1.12",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bcpkix-fips 1.0.12, 2.0.12 and 2.1.12",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bcpkix-fips", new F(true, new V[]{new V(null, "1.0.12"), new V(null, "2.0.12"), new V(null, "2.1.12")})),
                new String[]{"bcpkix"}));
        RULES.add(new Rule("CVE-2026-12803", "KCCMBlockCipher MAC does not bind nonce when AAD is absent (cross-nonce AEAD forgery)", false,
                "BC before 1.85, BC-LTS before 2.73.12",
                "BC 1.85, BC-LTS 2.73.12",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips(),
                new String[]{}));
        RULES.add(new Rule("CVE-2026-12816", "IESEngine stream-mode MAC forgery via length-dependent KDF split", false,
                "BC before 1.85, BC-LTS before 2.73.12",
                "BC 1.85, BC-LTS 2.73.12",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips(),
                new String[]{}));
        RULES.add(new Rule("CVE-2026-12817", "OpenPGP AEAD decryption skips final tag on chunk-aligned data", false,
                "BC before 1.85 (from 1.74), BC-LTS before 2.73.12, BC-FJA before bcpg-fips 1.0.13 (from 1.0.7), 2.0.13 and 2.1.13",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bcpg-fips 1.0.13 (from 1.0.7), 2.0.13 and 2.1.13",
                new V[]{new V("1.74", "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bcpg-fips", new F(true, new V[]{new V("1.0.7", "1.0.13"), new V(null, "2.0.13"), new V(null, "2.1.13")})),
                new String[]{"bcpg"}));
        RULES.add(new Rule("CVE-2026-12852", "MLS wire decoder allocates attacker-declared opaque length before bounds check", false,
                "BC before 1.85 (from 1.73)",
                "BC 1.85",
                new V[]{new V("1.73", "1.85")}, true,
                new V[]{}, false, null,
                fips(),
                new String[]{}));
        RULES.add(new Rule("CVE-2026-12860", "RSA PKCS#1 verification skips last two hash bytes in NULL-omitted path", false,
                "BC before 1.85, BC-LTS before 2.73.12",
                "BC 1.85, BC-LTS 2.73.12",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips(),
                new String[]{}));
        RULES.add(new Rule("CVE-2026-13506", "Lazy ASN.1 sequence forcing resets nesting-depth guard", false,
                "BC before 1.85, BC-LTS before 2.73.12, BC-FJA before bc-fips 1.0.2.7, 2.0.2 and 2.1.3",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bc-fips 1.0.2.7, 2.0.2 and 2.1.3",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bc-fips", new F(true, new V[]{new V(null, "1.0.2.7"), new V(null, "2.0.2"), new V(null, "2.1.3")})),
                new String[]{"bcprov"}));
        RULES.add(new Rule("CVE-2026-13586", "PKCS#12 MAC and bag-decryption KDF iteration-count bound (DoS)", false,
                "BC before 1.85, BC-LTS before 2.73.12, BC-FJA before bc-fips 1.0.2.7, 2.0.2 and 2.1.3",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bc-fips 1.0.2.7, 2.0.2 and 2.1.3",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bc-fips", new F(true, new V[]{new V(null, "1.0.2.7"), new V(null, "2.0.2"), new V(null, "2.1.3")})),
                new String[]{"bcprov"}));
        RULES.add(new Rule("CVE-2026-14682", "Possible OOM from unbounded up-front allocation on a definite-length read", false,
                "BC before 1.85, BC-LTS before 2.73.12, BC-FJA before bc-fips 1.0.2.7, 2.0.2 and 2.1.3, BC-FJA before bctls-fips 1.0.24",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bc-fips 1.0.2.7, 2.0.2 and 2.1.3, BC-FJA bctls-fips 1.0.24",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bc-fips", new F(true, new V[]{new V(null, "1.0.2.7"), new V(null, "2.0.2"), new V(null, "2.1.3")}), "bctls-fips", new F(true, new V[]{new V(null, "1.0.24")})),
                new String[]{"bcprov", "bctls"}));
        RULES.add(new Rule("CVE-2026-15055", "PKCS#8 / PBES2 decryptors honour unbounded KDF cost from input", false,
                "BC before 1.85, BC-LTS before 2.73.12, BC-FJA before bcpkix-fips 1.0.12, 2.0.12 and 2.1.12",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bcpkix-fips 1.0.12, 2.0.12 and 2.1.12",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bcpkix-fips", new F(true, new V[]{new V(null, "1.0.12"), new V(null, "2.0.12"), new V(null, "2.1.12")})),
                new String[]{"bcpkix"}));
        RULES.add(new Rule("CVE-2026-3505", "Unbounded PGP AEAD chunk size leads to pre-auth resource exhaustion", false,
                "BC 1.74 to 1.80.1, BC 1.81, BC 1.82 to BC 1.83",
                "BC 1.80.2, BC 1.81.1, BC 1.84",
                new V[]{new V("1.74", "1.80.1"), new V("1.81", "1.81"), new V("1.82", "1.83")}, false,
                new V[]{}, false, null,
                fips(),
                new String[]{}));
        RULES.add(new Rule("CVE-2026-5588", "PKIX draft CompositeVerifier accepts empty signature sequence as valid", false,
                "BC 1.67 to 1.80.1, BC 1.81, BC 1.82 to BC 1.83. BCPKIX-FIPS 2.0.6 to 2.0.10. BCPKIX-FIPS 2.1.7 to 2.1.10. BCPKIX-LTS 2.73.7 to 2.73.10",
                "BC 1.80.2, BC 1.81.1, BC 1.84, BCPKIX-FIPS 2.0.11, BCPKIX-FIPS 2.1.11, BCPKIX-LTS 2.73.11",
                new V[]{new V("1.67", "1.80.1"), new V("1.81", "1.81"), new V("1.82", "1.83")}, false,
                new V[]{new V("2.73.7", "2.73.10")}, false, "bcpkix",
                fips("bcpkix-fips", new F(false, new V[]{new V("2.0.6", "2.0.10"), new V("2.1.7", "2.1.10")})),
                new String[]{"bcpkix"}));
        RULES.add(new Rule("CVE-2026-5598", "Non-constant time comparisons risk private key leakage in FrodoKEM", false,
                "BC 1.71 to 1.80.1, BC 1.81, BC 1.82 to BC 1.83",
                "BC 1.80.2, BC 1.81.1, BC 1.84",
                new V[]{new V("1.71", "1.80.1"), new V("1.81", "1.81"), new V("1.82", "1.83")}, false,
                new V[]{}, false, null,
                fips(),
                new String[]{}));
        RULES.add(new Rule("CVE-2026-58059", "Quadratic-time escaping when stringifying X.500 distinguished names", false,
                "BC before 1.85, BC-LTS before 2.73.12, BC-FJA before bc-fips 1.0.2.7, 2.0.2 and 2.1.3",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bc-fips 1.0.2.7, 2.0.2 and 2.1.3",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bc-fips", new F(true, new V[]{new V(null, "1.0.2.7"), new V(null, "2.0.2"), new V(null, "2.1.3")})),
                new String[]{"bcprov"}));
        RULES.add(new Rule("CVE-2026-58060", "HSS public-key level count unbounded, enabling huge allocation on verify", false,
                "BC before 1.85 (from 1.65), BC-LTS before 2.73.12, BC-FJA before bc-fips 2.0.2 and 2.1.3",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bc-fips 2.0.2 and 2.1.3",
                new V[]{new V("1.65", "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bc-fips", new F(true, new V[]{new V(null, "2.0.2"), new V(null, "2.1.3")})),
                new String[]{"bcprov"}));
        RULES.add(new Rule("CVE-2026-58061", "CCM-family modes write plaintext to caller buffer before tag check", false,
                "BC before 1.85, BC-LTS before 2.73.12, BC-FJA before bc-fips 1.0.2.7, 2.0.2 and 2.1.3",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bc-fips 1.0.2.7, 2.0.2 and 2.1.3",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bc-fips", new F(true, new V[]{new V(null, "1.0.2.7"), new V(null, "2.0.2"), new V(null, "2.1.3")})),
                new String[]{"bcprov"}));
        RULES.add(new Rule("CVE-2026-58062", "Stapled OCSP response accepted without binding to the checked certificate", true,
                "BC before 1.85 (from 1.66), BC-LTS before 2.73.12, BC-FJA before bc-fips 2.0.2 and 2.1.3",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bc-fips 2.0.2 and 2.1.3",
                new V[]{new V("1.66", "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bc-fips", new F(true, new V[]{new V(null, "2.0.2"), new V(null, "2.1.3")})),
                new String[]{"bcprov"}));
        RULES.add(new Rule("CVE-2026-58063", "BCFKS keystore load honours unbounded KDF cost from untrusted file", false,
                "BC before 1.85, BC-LTS before 2.73.12, BC-FJA before bc-fips 1.0.2.7, 2.0.2 and 2.1.3",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bc-fips 1.0.2.7, 2.0.2 and 2.1.3",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bc-fips", new F(true, new V[]{new V(null, "1.0.2.7"), new V(null, "2.0.2"), new V(null, "2.1.3")})),
                new String[]{"bcprov"}));
        RULES.add(new Rule("CVE-2026-59638", "JSSE hostname verifier CN-fallback enabled by default despite documented opt-in", true,
                "BC before 1.85 (from 1.61), BC-LTS before 2.73.12, BC-FJA before bctls-fips 1.0.24 (from 1.0.7), 2.0.24 and 2.1.24",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bctls-fips 1.0.24 (from 1.0.7), 2.0.24 and 2.1.24",
                new V[]{new V("1.61", "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bctls-fips", new F(true, new V[]{new V("1.0.7", "1.0.24"), new V(null, "2.0.24"), new V(null, "2.1.24")})),
                new String[]{"bctls"}));
        RULES.add(new Rule("CVE-2026-59639", "CMS verifySignatures returns true for SignedData with zero signers", false,
                "BC before 1.85, BC-LTS before 2.73.12, BC-FJA before bcpkix-fips 1.0.12, 2.0.12 and 2.1.12",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bcpkix-fips 1.0.12, 2.0.12 and 2.1.12",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bcpkix-fips", new F(true, new V[]{new V(null, "1.0.12"), new V(null, "2.0.12"), new V(null, "2.1.12")})),
                new String[]{"bcpkix"}));
        RULES.add(new Rule("CVE-2026-59640", "OpenPGP CFB quick-check oracle active on symmetric/session-key paths", false,
                "BC before 1.85, BC-LTS before 2.73.12, BC-FJA before bcpg-fips 1.0.13, 2.0.13 and 2.1.13",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bcpg-fips 1.0.13, 2.0.13 and 2.1.13",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bcpg-fips", new F(true, new V[]{new V(null, "1.0.13"), new V(null, "2.0.13"), new V(null, "2.1.13")})),
                new String[]{"bcpg"}));
        RULES.add(new Rule("CVE-2026-59641", "S/MIME validator trusts signer-asserted signingTime for path validation", false,
                "BC before 1.85, BC-LTS before 2.73.12, BC-FJA before bcmail-fips 1.0.7, 2.0.7 and 2.1.7, BC-FJA before bcjmail-fips 1.0.7 (from 1.0.4), 2.0.7 and 2.1.7",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bcmail-fips 1.0.7, 2.0.7 and 2.1.7 and bcjmail-fips 1.0.7 (from 1.0.4), 2.0.7 and 2.1.7",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bcmail-fips", new F(true, new V[]{new V(null, "1.0.7"), new V(null, "2.0.7"), new V(null, "2.1.7")}), "bcjmail-fips", new F(true, new V[]{new V("1.0.4", "1.0.7"), new V(null, "2.0.7"), new V(null, "2.1.7")})),
                new String[]{"bcjmail", "bcmail"}));
        RULES.add(new Rule("CVE-2026-59642", "CMS AuthenticatedData content not bound to MAC when authAttrs present", false,
                "BC before 1.85, BC-LTS before 2.73.12, BC-FJA before bcpkix-fips 1.0.12, 2.0.12 and 2.1.12",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bcpkix-fips 1.0.12, 2.0.12 and 2.1.12",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bcpkix-fips", new F(true, new V[]{new V(null, "1.0.12"), new V(null, "2.0.12"), new V(null, "2.1.12")})),
                new String[]{"bcpkix"}));
        RULES.add(new Rule("CVE-2026-59643", "OpenPGP inline-signature policy failures silently ignored", false,
                "BC before 1.85 (from 1.81), BC-FJA before bcpg-fips 2.0.13 (from 2.0.12)",
                "BC 1.85, BC-FJA bcpg-fips 2.0.13",
                new V[]{new V("1.81", "1.85")}, true,
                new V[]{}, false, null,
                fips("bcpg-fips", new F(true, new V[]{new V("2.0.12", "2.0.13")})),
                new String[]{"bcpg"}));
        RULES.add(new Rule("CVE-2026-59644", "MLS hash-ratchet honours arbitrary 32-bit generation counter from sender", false,
                "BC before 1.85 (from 1.73)",
                "BC 1.85",
                new V[]{new V("1.73", "1.85")}, true,
                new V[]{}, false, null,
                fips(),
                new String[]{}));
        RULES.add(new Rule("CVE-2026-59645", "OER parser recurses without depth limit on self-referential IEEE 1609.2 schema", false,
                "BC before 1.85 (from 1.70), BC-LTS before 2.73.12, BC-FJA before bcutil-fips 2.0.7 and 2.1.7",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bcutil-fips 2.0.7 and 2.1.7",
                new V[]{new V("1.70", "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bcutil-fips", new F(true, new V[]{new V(null, "2.0.7"), new V(null, "2.1.7")})),
                new String[]{"bcutil"}));
        RULES.add(new Rule("CVE-2026-59646", "DTLS handshake reassembler allocates buffer from unchecked 24-bit length", false,
                "BC before 1.85, BC-LTS before 2.73.12, BC-FJA before bctls-fips 1.0.24, 2.0.24 and 2.1.24",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bctls-fips 1.0.24, 2.0.24 and 2.1.24",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bctls-fips", new F(true, new V[]{new V(null, "1.0.24"), new V(null, "2.0.24"), new V(null, "2.1.24")})),
                new String[]{"bctls"}));
        RULES.add(new Rule("CVE-2026-59647", "CRMF/CMP password-MAC honours unbounded iteration count", false,
                "BC before 1.85, BC-LTS before 2.73.12, BC-FJA before bcpkix-fips 1.0.12, 2.0.12 and 2.1.12",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bcpkix-fips 1.0.12, 2.0.12 and 2.1.12",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bcpkix-fips", new F(true, new V[]{new V(null, "1.0.12"), new V(null, "2.0.12"), new V(null, "2.1.12")})),
                new String[]{"bcpkix"}));
        RULES.add(new Rule("CVE-2026-59648", "OpenPGP Argon2 S2K honours attacker-chosen memory and passes", false,
                "BC before 1.85 (from 1.71), BC-LTS before 2.73.12, BC-FJA before bcpg-fips 1.0.13 (from 1.0.6), 2.0.13 and 2.1.13",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bcpg-fips 1.0.13 (from 1.0.6), 2.0.13 and 2.1.13",
                new V[]{new V("1.71", "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bcpg-fips", new F(true, new V[]{new V("1.0.6", "1.0.13"), new V(null, "2.0.13"), new V(null, "2.1.13")})),
                new String[]{"bcpg"}));
        RULES.add(new Rule("CVE-2026-59649", "OpenPGP user-attribute subpacket length bounded only by JVM max memory", false,
                "BC before 1.85, BC-LTS before 2.73.12, BC-FJA before bcpg-fips 1.0.13, 2.0.13 and 2.1.13",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bcpg-fips 1.0.13, 2.0.13 and 2.1.13",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bcpg-fips", new F(true, new V[]{new V(null, "1.0.13"), new V(null, "2.0.13"), new V(null, "2.1.13")})),
                new String[]{"bcpg"}));
        RULES.add(new Rule("CVE-2026-59650", "MTI/A0 DH agreement exponentiates unvalidated peer value", true,
                "BC before 1.85, BC-LTS before 2.73.12",
                "BC 1.85, BC-LTS 2.73.12",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips(),
                new String[]{}));
        RULES.add(new Rule("CVE-2026-59651", "BKS keystore accepts legacy version with 16-bit integrity MAC key", false,
                "BC before 1.85, BC-LTS before 2.73.12",
                "BC 1.85, BC-LTS 2.73.12",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips(),
                new String[]{}));
        RULES.add(new Rule("CVE-2026-59652", "LDAP filter injection in legacy jdk1.4 LDAPStoreHelper", false,
                "BC before 1.85",
                "BC 1.85",
                new V[]{new V(null, "1.85")}, true,
                new V[]{}, false, null,
                fips(),
                new String[]{}));
        RULES.add(new Rule("CVE-2026-8149", "GCM chunking can lead to bad tag exception on decryption", false,
                "BC-LTS 2.73.0 to 2.73.10",
                "BC-LTS 2.73.11",
                new V[]{}, false,
                new V[]{new V("2.73.0", "2.73.10")}, false, null,
                fips(),
                new String[]{}));
        RULES.add(new Rule("CVE-2026-8763", "Name Constraints bypass via trailing dot in rfc822Name and URI", true,
                "BC before 1.85, BC-LTS before 2.73.12, BC-FJA before bc-fips 1.0.2.7, 2.0.2 and 2.1.3",
                "BC 1.85, BC-LTS 2.73.12, BC-FJA bc-fips 1.0.2.7, 2.0.2 and 2.1.3",
                new V[]{new V(null, "1.85")}, true,
                new V[]{new V(null, "2.73.12")}, true, null,
                fips("bc-fips", new F(true, new V[]{new V(null, "1.0.2.7"), new V(null, "2.0.2"), new V(null, "2.1.3")})),
                new String[]{"bcprov"}));
    }

    private CveTable() {
    }
}
