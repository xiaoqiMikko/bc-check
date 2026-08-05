# bc-check

**离线排查你的 Java 应用受 Bouncy Castle 2026 年这批 CVE 的哪几条影响。**
零依赖、单个 jar、不联网、不上传任何数据。

```
java -jar bc-check.jar ./app.jar
java -jar bc-check.jar --gav bcprov-lts8on:2.73.5 --detail
```

---

## 为什么需要一个工具（而不是看一眼版本号）

官方所有 CVE 描述统一写的是一句话：

> Bouncy Castle for Java **before 1.85**

**但真正在用的人里，有两条产品线的版本号根本不长这样：**

| 产品线 | artifact 形如 | 版本号形如 | 「before 1.85」对他有用吗 |
|---|---|---|---|
| BC（常规版） | `bcprov-jdk18on` | `1.81` | ✅ 有用 |
| BC-LTS（长期支持版） | `bcprov-lts8on` | `2.73.5` | ❌ 完全无从判断 |
| BC-FJA（FIPS 认证版） | `bc-fips` / `bctls-fips` … | `1.0.2.5` / `2.0.1` / `2.1.2` | ❌ 完全无从判断 |

三条线的修复版分别是 **1.85**、**2.73.12**、以及 **7 个 FIPS artifact 各自的一套版本号**。
它们不在同一条数轴上，互相比对没有意义。

### 四个例子，说明为什么一刀切会给出错误结论

1. **`CVE-2026-8149` 压根不影响 BC 线**，只影响 BC-LTS `2.73.0`–`2.73.10`。
   盯着「1.85」这个版本号的人，永远发现不了它。
2. **`CVE-2026-59650` 完全不影响 FIPS 版**。按「before 1.85」去报，是虚惊一场。
3. **`CVE-2026-59638` 在 FIPS 侧要查的 artifact 是 `bctls-fips`，不是 `bc-fips`** ——
   从加密核心换到了 TLS 模块。只盯着 `bc-fips` 的人查不到。
4. **`CVE-2026-58062` 与 `58060` 官方只列了 `bc-fips` 的 `2.0.2` 和 `2.1.3`，没有 `1.0.x`** ——
   意思是 `1.0.x` 线不受影响。而 `CVE-2026-8763` 列了 `1.0.2.7`，`1.0.x` 就受影响。
   **同一个 artifact、同一个版本，不同 CVE 给出不同答案。**

还有 **10 条 CVE 有起始受影响版本**（`from 1.61`、`from 1.66`、`from 1.73` 各不相同），
不是「全版本受影响」；另有 4 条老 CVE 的修复版是 `1.80.2` / `1.81.1` / `1.84` 这样的**分支版本**，
受影响区间是**断开的**（`1.74`–`1.80.1`，`1.81`，`1.82`–`1.83`）。

> **假设你已经读完了所有公告、知道了全部答案，你依然查不了** ——
> 因为答案不是一个版本号，是一张「产品线 × artifact × CVE」的三维表。

## 还有一件事：这批 CVE 你的 Dependabot 大概率不会告警

**这 4 条 CVSS critical** 在 GitHub Advisory 里的状态是 `unreviewed`，
**受影响包列表是空的**（包数 0）。没有包名就无法匹配依赖树 ——
它们不进 OSV，Dependabot 不告警，SCA 扫依赖清单也扫不出来。

拿 `org.bouncycastle:bcprov-jdk18on:1.81` 查 OSV，命中的是另外两条
（`CVE-2025-14813`、`CVE-2026-0636`），**这 4 条 critical 一条都不在**。

> ⚠️ 说清楚边界：**不是「BC 的漏洞 Dependabot 全看不见」** ——
> 同一批里的 `CVE-2026-0636` 就是 reviewed、有包信息、正常告警的。
> 看不见的是这 4 条 critical。

| CVE | GHSA | 状态 | 包数 |
|---|---|---|---|
| CVE-2026-58062 | GHSA-j295-77c3-9frf | unreviewed | 0 |
| CVE-2026-8763 | GHSA-9pwp-9qqc-pr26 | unreviewed | 0 |
| CVE-2026-59650 | GHSA-ghgq-7g74-28wp | unreviewed | 0 |
| CVE-2026-59638 | GHSA-8rxj-3p7p-rq39 | unreviewed | 0 |

## 用法

```
java -jar bc-check.jar <路径> [更多路径...] [选项]
java -jar bc-check.jar --gav <坐标>
```

路径可以是 jar / war 文件（含 Spring Boot fat-JAR，自动逐层展开），也可以是目录（递归）。

| 选项 | 说明 |
|---|---|
| `--gav <坐标>` | 不扫文件，直接判定一个坐标，如 `bcprov-lts8on:2.73.5` |
| `-d, --detail` | 逐条列出命中的 CVE 与官方原文 |
| `--json` | 输出 JSON，便于接流水线（恒为 UTF-8） |
| `--utf8` / `--gbk` | 控制台中文乱码时强制指定编码 |
| `--no-color` | 关闭彩色输出 |

退出码：`0` = 未命中；`1` = 命中 CVE；`2` = 用法错误。可直接用作 CI 门禁。

### 输出长这样

```
[CRITICAL] bcprov-lts8on 2.73.5　BC-LTS 线
  位置　　：app.jar!/BOOT-INF/lib/bcprov-lts8on-2.73.5.jar
  来源　　：jar 内 MANIFEST
  结论　　：命中 29 条 CVE，其中 CVSS critical 4 条
  降噪　　：其中 13 条按官方 FIPS 侧点名的 artifact 反推，大概率出在 bcpkix / bcpg / bctls 模块。
            ⚠️ 这是推断不是官方结论，仅供排优先级。
  处置　　：升级到 2.73.12（BC-LTS 线）
```

## 它怎么找到 Bouncy Castle 的

BC 绝大多数情况**不是你自己引的**，是被传递依赖拖进来的 ——
TLS、证书校验、JWT、PDF 签名、PGP 都会引它。所以本工具不看 pom，只看真实产物：

1. `META-INF/MANIFEST.MF` 的 `Bundle-SymbolicName` + `Bundle-Version`（**主路径**）
2. jar 文件名
3. `META-INF/maven/org.bouncycastle/*/pom.properties`（官方 jar 里没有，重打包的才有）
4. 只找到 `org/bouncycastle/` 的 class 但认不出坐标 → 报 `UNKNOWN` 并提示手工确认

第 4 种是被 shade 进宿主 jar 的情况，`mvn dependency:tree` 和 SCA 都看不见它，
**本工具至少会告诉你「这里有 BC，但我认不出版本」，而不是悄悄漏掉。**

> jar 被改名（内部制品库重发布很常见）时，文件名认不出，MANIFEST 依然认得出。

## 判定依据从哪来

全部来自官方 `github.com/bcgit/bc-java` wiki 上 **2026 年 37 条 CVE 的逐条子页面**
（`Issue affecting` / `Fixed versions` 原文），不是二手转述、不是聚合文章。

- 一手数据：[`tools/data/bc_cves.json`](tools/data/bc_cves.json)
- 判定表由 [`tools/gen_rules.py`](tools/gen_rules.py) 自动生成成 `CveTable.java`，**不手抄**
- 报告里逐条附上官方原文，你可以自己核对

重新生成：`python tools/gen_rules.py`

### 🔴 判定范围（看到 OK 之前先读这段）

本工具只覆盖官方 wiki 上 **2026 年的 37 条 CVE**。
**2026 年之前的 Bouncy Castle 漏洞不在范围内** —— 那些多数已进 OSV，
Dependabot / SCA 查得到，本工具不重复造轮子。

举个具体的：`org.bouncycastle:bcprov-jdk18on:1.81` 在 OSV 里能查到
`CVE-2025-14813` 和 `CVE-2026-0636` —— 前者本工具**不覆盖**（2025 年），
后者覆盖。所以本工具报 `OK` 的意思是「**不受 2026 年这批影响**」，
不是「你的 Bouncy Castle 完全没问题」。**两者要一起看，不是二选一。**

### 已知的口径问题（不藏着）

- 官方 release 页说「1.85 修了 23 个 CVE」，而 wiki 上 2026 年共 **37 条** ——
  **两者不是同一个集合**（37 条里有些修复版是 `1.84` / `1.80.2` 等更早的分支版本）。
  本工具按 wiki 逐条判定，不使用「23 个」这个数字。
- `1.85.1` 与 `2.73.12.1` 都是**打包修正**（官方 release notes 原文：packaging issue），
  **不是独立的安全修复版**。停在 `1.85` 不会因此漏修。
- `CVE-2026-14682` 官方在 FIPS 侧只写了 `bctls-fips 1.0.24`，没有 `2.0.24 / 2.1.24`，
  与同类的 `CVE-2026-59646` 写法不一致。**本工具照官方原文判定**，不替官方补全。
- 「大概率属其他模块」是本工具按 FIPS 侧点名的 artifact 做的**推断** ——
  官方对 BC / BC-LTS 线只写「before 1.85」，不指明 artifact。
  该提示**只用于排优先级，绝不能据此认定你不受影响**。

## 构建

```
mvn package        # 产物 target/bc-check.jar
```

编译目标 Java 8：应急排查工具要能直接丢到生产机器上跑，而企业环境里大量 JRE 仍是 8。
零运行时依赖 —— 排查 Bouncy Castle 的工具，自己不能依赖 Bouncy Castle。

## License

Apache License 2.0
