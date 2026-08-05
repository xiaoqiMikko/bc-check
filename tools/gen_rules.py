# -*- coding: utf-8 -*-
"""把 bcgit 官方 wiki 的一手 CVE 数据(data/bc_cves.json)编译成 Java 规则表。

为什么要生成而不是手写:37 条 CVE × 3 条产品线 × 7 个 FIPS artifact,
手抄一定会错;而这个工具的价值全部押在「判定是对的」上面 ——
第一注的教训:判定规则错了不是误报,是让用户做错事。

用法:
    python tools/gen_rules.py          # 生成 CveTable.java
    python tools/gen_rules.py --check  # 只解析并打印,人工核对,不写文件

数据来源:https://github.com/bcgit/bc-java/wiki/CVEs 逐条子页面,
由 projectExtend/.claude/scripts/bc_cve_scrape.py 拉取。
"""
import json
import re
import sys
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "src/main/java/io/mikko/bccheck/CveTable.java"
DATA = ROOT / "tools/data/bc_cves.json"

# 官方只对这 4 条给出了 CVSS critical 评级(NVD 已核实,见 docs/bets/4-bouncycastle.md)。
# 其余 33 条 wiki 未标注等级,工具里一律标「未标注」,不猜。
CRITICAL = {"CVE-2026-58062", "CVE-2026-8763", "CVE-2026-59650", "CVE-2026-59638"}

# FIPS artifact ↔ 非 FIPS 模块的对应关系。
# ⚠️ 这是**推断**,不是官方原文:官方对 BC / BC-LTS 线只写「before 1.85」,
# 不指明是哪个 artifact 出的问题,只有 FIPS 侧点了名。
# 因此本映射**只用于降噪提示**(「这条大概率与你无关」),绝不用于判定安全与否。
FIPS_TO_MODULE = {
    "bc-fips": "bcprov",
    "bctls-fips": "bctls",
    "bcpkix-fips": "bcpkix",
    "bcpg-fips": "bcpg",
    "bcmail-fips": "bcmail",
    "bcjmail-fips": "bcjmail",
    "bcutil-fips": "bcutil",
}


def norm(s):
    """统一大小写与空白,官方原文里 BCPKIX-FIPS / bcpkix-fips 混用。"""
    return re.sub(r"\s+", " ", s).strip()


def ver(s):
    """清掉版本号尾部的句点 —— 官方原文里 "BC 1.83." 的点是句号不是版本分隔符。"""
    return s.rstrip(".") if s else s


def parse_bc(text):
    """解析 BC(非 FIPS、非 LTS)线的受影响范围。

    两种写法:
      - "BC before 1.85" / "BC before 1.85 (from 1.66)"  -> 开区间
      - "BC 1.74 to 1.80.1, BC 1.81, BC 1.82 to BC 1.83" -> 若干闭区间
    返回 (kind, ranges);kind 为 "before" 或 "ranges" 或 None。
    """
    # 版本号用 \d[\d.]*\d|\d 贪婪匹配,避免把 "1.85" 截成 "1"(尾部句点由 ver() 清掉)
    m = re.search(r"\bBC before (\d[\d.]*)(?:\s*\(from (\d[\d.]*)\))?", text)
    if m:
        return ("before", [(ver(m.group(2)), ver(m.group(1)))])

    ranges = []
    # "BC 1.74 to 1.80.1" / "BC 1.82 to BC 1.83" / 单点 "BC 1.81"
    for seg in re.finditer(r"\bBC (\d[\d.]*)(?:\s+to\s+(?:BC\s+)?(\d[\d.]*))?", text):
        # 避开 BC-LTS / BC-FJA 前缀(上面的正则里 "BC " 后必须紧跟数字,已天然排除)
        lo, hi = ver(seg.group(1)), ver(seg.group(2) or seg.group(1))
        ranges.append((lo, hi))
    return ("ranges", ranges) if ranges else (None, [])


def parse_lts(text):
    """解析 BC-LTS 线。写法:"BC-LTS before 2.73.12" 或 "BC-LTS 2.73.0 to 2.73.10"。

    ⚠️ 还有一种带模块名的:"BCPKIX-LTS 2.73.7 to 2.73.10"(仅 CVE-2026-5588),
    它只影响 LTS 线的 bcpkix,不是整条 LTS 线 —— 单独返回模块名。
    """
    m = re.search(r"\bBC-LTS before (\d[\d.]*)", text)
    if m:
        return ("before", None, [(None, ver(m.group(1)))])
    m = re.search(r"\bBC-LTS (\d[\d.]*)\s+to\s+(\d[\d.]*)", text)
    if m:
        return ("ranges", None, [(ver(m.group(1)), ver(m.group(2)))])
    m = re.search(r"\b(BC[A-Z]+)-LTS (\d[\d.]*)\s+to\s+(\d[\d.]*)", text, re.I)
    if m:
        return ("ranges", m.group(1).lower(), [(ver(m.group(2)), ver(m.group(3)))])
    return (None, None, [])


def parse_fips(text):
    """解析 BC-FJA(FIPS)线,返回 {artifact: [(from, fixed), ...]}。

    写法一(多数):"BC-FJA before bc-fips 1.0.2.7, 2.0.2 and 2.1.3"
        -> 1.0.x 线修复版 1.0.2.7、2.0.x 线 2.0.2、2.1.x 线 2.1.3。
           **没被列出的版本线 = 不受影响**,这正是一刀切查不出来的东西。
    写法二(带起始版本):"bcpg-fips 1.0.13 (from 1.0.7), 2.0.13 and 2.1.13"
    写法三(闭区间,仅 CVE-2026-5588):"BCPKIX-FIPS 2.0.6 to 2.0.10"
        -> 上界含,且修复版只写在 Fixed versions 栏里。

    返回值:{artifact: {"before": bool, "entries": [(from, upper), ...]}}
    """
    out = {}
    # 写法一/二:"BC-FJA before <artifact> <版本清单>",清单一直吃到下一个 BC-FJA 或句尾
    for m in re.finditer(r"BC-FJA before (bc[a-z]*-fips)\s+(.*?)(?=,\s*BC-FJA|$)", text):
        art = m.group(1).lower()
        entries = []
        for v in re.finditer(r"(\d[\d.]*)(?:\s*\(from (\d[\d.]*)\))?", m.group(2)):
            entries.append((ver(v.group(2)), ver(v.group(1))))
        if entries:
            out.setdefault(art, {"before": True, "entries": []})["entries"].extend(entries)

    # 写法三:闭区间,写法与前两种互斥
    for m in re.finditer(r"\b(BC[A-Z]+)-FIPS (\d[\d.]*)\s+to\s+(\d[\d.]*)", text, re.I):
        art = (m.group(1) + "-fips").lower()
        out.setdefault(art, {"before": False, "entries": []})["entries"].append(
            (ver(m.group(2)), ver(m.group(3))))
    return out


def main():
    rows = json.loads(DATA.read_text(encoding="utf-8"))
    parsed = []
    for r in rows:
        aff = norm(r["affecting"])
        fix = norm(r["fixed"])
        bc_kind, bc_ranges = parse_bc(aff)
        lts_kind, lts_module, lts_ranges = parse_lts(aff)
        fips = parse_fips(aff)
        modules = sorted({FIPS_TO_MODULE[a] for a in fips if a in FIPS_TO_MODULE})
        parsed.append({
            "cve": r["cve"], "title": norm(r["title"]),
            "affecting": aff, "fixed": fix,
            "bc_kind": bc_kind, "bc_ranges": bc_ranges,
            "lts_kind": lts_kind, "lts_module": lts_module, "lts_ranges": lts_ranges,
            "fips": fips, "modules": modules,
            "critical": r["cve"] in CRITICAL,
        })

    if "--check" in sys.argv:
        for p in parsed:
            fips = "; ".join(
                "%s%s%s" % (a, "<" if d["before"] else "=", d["entries"])
                for a, d in p["fips"].items()) or "-"
            print("%-16s BC=%s%s LTS=%s%s%s FIPS=%s mod=%s" % (
                p["cve"], p["bc_kind"] or "-", p["bc_ranges"] or "",
                p["lts_kind"] or "-", p["lts_ranges"] or "",
                ("@" + p["lts_module"]) if p["lts_module"] else "",
                fips, ",".join(p["modules"]) or "-"))
        print("\n共 %d 条" % len(parsed))
        return

    SRC.write_text(render(parsed), encoding="utf-8")
    print("已生成 %s(%d 条规则)" % (SRC, len(parsed)))


def jstr(s):
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def jrange(entries):
    """(from, upper) 列表 -> Java 数组字面量。from 为 null 表示不限下界。"""
    return "{" + ", ".join(
        "new V(%s, %s)" % (jstr(f) if f else "null", jstr(u)) for f, u in entries) + "}"


def render(parsed):
    lines = []
    a = lines.append
    a("package io.mikko.bccheck;")
    a("")
    a("import java.util.ArrayList;")
    a("import java.util.Arrays;")
    a("import java.util.Collections;")
    a("import java.util.LinkedHashMap;")
    a("import java.util.List;")
    a("import java.util.Map;")
    a("")
    a("/**")
    a(" * Bouncy Castle CVE 判定表 —— <b>本文件由 tools/gen_rules.py 自动生成，不要手改</b>。")
    a(" *")
    a(" * <p>数据源：{@code tools/data/bc_cves.json}，逐条抓自官方")
    a(" * {@code github.com/bcgit/bc-java/wiki} 的 CVE 子页面（一手，非二手转述）。")
    a(" * 重新生成：{@code python tools/gen_rules.py}。")
    a(" *")
    a(" * <p>为什么不能照「Bouncy Castle for Java before 1.85」一刀切判定：")
    a(" * <ul>")
    a(" *   <li>BC-LTS 用户的版本号是 {@code 2.73.x}、FIPS 用户是 {@code 1.0.x / 2.0.x / 2.1.x}，")
    a(" *       拿「before 1.85」去比对，三条产品线里有两条完全无从判断。</li>")
    a(" *   <li>有 CVE 只影响单一产品线：{@code CVE-2026-8149} 压根不影响 BC，只影响 BC-LTS。</li>")
    a(" *   <li>FIPS 侧逐条不同：同一批漏洞里，有的要查 {@code bc-fips}，")
    a(" *       有的要查 {@code bctls-fips}，还有的 FIPS 根本不受影响。</li>")
    a(" *   <li>10 条 CVE 有起始受影响版本，不是「全版本受影响」。</li>")
    a(" * </ul>")
    a(" */")
    a("public final class CveTable {")
    a("")
    a("    /** 一段版本区间。{@code from} 为 null 表示不限下界（即「before X」型）。 */")
    a("    public static final class V {")
    a("        public final String from;")
    a("        public final String upper;")
    a("")
    a("        V(String from, String upper) {")
    a("            this.from = from;")
    a("            this.upper = upper;")
    a("        }")
    a("    }")
    a("")
    a("    /** 某个 FIPS artifact 的受影响规则。 */")
    a("    public static final class F {")
    a("        /**")
    a("         * true = 「before X」型：各版本线小于 X 即受影响，<b>且未被列出的版本线不受影响</b>。")
    a("         * false = 闭区间型（上界含），官方只对 CVE-2026-5588 用了这种写法。")
    a("         */")
    a("        public final boolean before;")
    a("        public final V[] lines;")
    a("")
    a("        F(boolean before, V[] lines) {")
    a("            this.before = before;")
    a("            this.lines = lines;")
    a("        }")
    a("    }")
    a("")
    a("    /** 一条 CVE 的完整判定规则。 */")
    a("    public static final class Rule {")
    a("        public final String cve;")
    a("        public final String title;")
    a("        public final boolean critical;")
    a("        /** 官方 Issue affecting 原文，报告里原样引用，避免转述走样。 */")
    a("        public final String affecting;")
    a("        /** 官方 Fixed versions 原文。 */")
    a("        public final String fixed;")
    a("        /** BC 线（jdk18on / jdk15to18 等）受影响区间；空数组表示不影响 BC 线。 */")
    a("        public final V[] bc;")
    a("        /** BC 线区间是否为「before」型（上界不含）。false 表示闭区间（上界含）。 */")
    a("        public final boolean bcBefore;")
    a("        /** BC-LTS 线受影响区间。 */")
    a("        public final V[] lts;")
    a("        public final boolean ltsBefore;")
    a("        /** 仅当该 CVE 只影响 LTS 线的某个模块时非 null（目前只有 CVE-2026-5588 的 bcpkix）。 */")
    a("        public final String ltsModule;")
    a("        /** FIPS：artifact -> 该 artifact 各版本线的受影响区间。 */")
    a("        public final Map<String, F> fips;")
    a("        /** 按 FIPS 侧 artifact 反推的相关模块，<b>推断值</b>，仅用于降噪提示。 */")
    a("        public final List<String> modules;")
    a("")
    a("        Rule(String cve, String title, boolean critical, String affecting, String fixed,")
    a("             V[] bc, boolean bcBefore, V[] lts, boolean ltsBefore, String ltsModule,")
    a("             Map<String, F> fips, String[] modules) {")
    a("            this.cve = cve;")
    a("            this.title = title;")
    a("            this.critical = critical;")
    a("            this.affecting = affecting;")
    a("            this.fixed = fixed;")
    a("            this.bc = bc;")
    a("            this.bcBefore = bcBefore;")
    a("            this.lts = lts;")
    a("            this.ltsBefore = ltsBefore;")
    a("            this.ltsModule = ltsModule;")
    a("            this.fips = fips;")
    a("            this.modules = Collections.unmodifiableList(Arrays.asList(modules));")
    a("        }")
    a("    }")
    a("")
    a("    private static final List<Rule> RULES = new ArrayList<Rule>();")
    a("")
    a("    /** 全部 %d 条规则，顺序与官方 wiki 一致。 */" % len(parsed))
    a("    public static List<Rule> rules() {")
    a("        return Collections.unmodifiableList(RULES);")
    a("    }")
    a("")
    a("    private static Map<String, F> fips(Object... kv) {")
    a("        Map<String, F> m = new LinkedHashMap<String, F>();")
    a("        for (int i = 0; i < kv.length; i += 2) {")
    a("            m.put((String) kv[i], (F) kv[i + 1]);")
    a("        }")
    a("        return m;")
    a("    }")
    a("")
    a("    static {")
    for p in parsed:
        fips_args = []
        for art, d in p["fips"].items():
            fips_args.append(jstr(art))
            fips_args.append("new F(%s, new V[]%s)" % (
                "true" if d["before"] else "false", jrange(d["entries"])))
        a("        RULES.add(new Rule(%s, %s, %s," % (jstr(p["cve"]), jstr(p["title"]),
                                                     "true" if p["critical"] else "false"))
        a("                %s," % jstr(p["affecting"]))
        a("                %s," % jstr(p["fixed"]))
        a("                new V[]%s, %s," % (jrange(p["bc_ranges"]),
                                             "true" if p["bc_kind"] == "before" else "false"))
        a("                new V[]%s, %s, %s," % (jrange(p["lts_ranges"]),
                                                 "true" if p["lts_kind"] == "before" else "false",
                                                 jstr(p["lts_module"]) if p["lts_module"] else "null"))
        a("                fips(%s)," % ", ".join(fips_args))
        a("                new String[]{%s}));" % ", ".join(jstr(m) for m in p["modules"]))
    a("    }")
    a("")
    a("    private CveTable() {")
    a("    }")
    a("}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    main()
