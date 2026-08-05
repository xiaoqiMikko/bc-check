package io.mikko.bccheck;

import java.util.ArrayList;
import java.util.List;

/**
 * 版本号比较与「版本线」归属。
 *
 * <p>Bouncy Castle 的版本号跨三条产品线共存：{@code 1.85}、{@code 2.73.12}、{@code 1.0.2.7}。
 * 段数不同（2 段 / 3 段 / 4 段），因此比较时缺失段一律按 0 处理。
 */
public final class Version {

    private Version() {
    }

    /**
     * 比较两个版本号，只比数值段，忽略 {@code -SNAPSHOT}、{@code .redhat-1} 等后缀。
     *
     * @return 负数表示 a &lt; b，0 相等，正数 a &gt; b；任一无法解析时返回 0
     */
    public static int compare(String a, String b) {
        int[] va = parse(a);
        int[] vb = parse(b);
        if (va == null || vb == null) {
            return 0;
        }
        for (int i = 0; i < Math.max(va.length, vb.length); i++) {
            int x = i < va.length ? va[i] : 0;
            int y = i < vb.length ? vb[i] : 0;
            if (x != y) {
                return x < y ? -1 : 1;
            }
        }
        return 0;
    }

    /**
     * 取版本所属的「版本线」，即前两段，如 {@code 1.0.2.7} → {@code 1.0}、{@code 2.73.12} → {@code 2.73}。
     *
     * <p>FIPS 线判定全靠它：官方写「before bc-fips 1.0.2.7, 2.0.2 and 2.1.3」时，
     * 意思是这三条版本线各有各的修复版；而写「before bc-fips 2.0.2 and 2.1.3」（少了 1.0.x）时，
     * <b>意思是 1.0.x 线根本不受这条 CVE 影响</b> —— 这正是「before 1.85」一刀切查不出来的东西。
     *
     * @return 形如 {@code "1.0"}；无法解析时返回 null
     */
    public static String lineOf(String version) {
        int[] v = parse(version);
        if (v == null) {
            return null;
        }
        return v.length >= 2 ? v[0] + "." + v[1] : String.valueOf(v[0]);
    }

    /** 两个版本是否属于同一条版本线。 */
    public static boolean sameLine(String a, String b) {
        String la = lineOf(a);
        String lb = lineOf(b);
        return la != null && la.equals(lb);
    }

    /**
     * 提取版本号的数值段。
     *
     * <p>遇到第一个非数字非点号的字符即停止：{@code 1.85-SNAPSHOT} → {@code [1,85]}。
     *
     * @return 无法解析时返回 null
     */
    public static int[] parse(String version) {
        if (version == null) {
            return null;
        }
        String v = version.trim();
        if (v.startsWith("v") || v.startsWith("V")) {
            v = v.substring(1);
        }
        List<Integer> nums = new ArrayList<Integer>();
        StringBuilder cur = new StringBuilder();
        for (int i = 0; i <= v.length(); i++) {
            char c = i < v.length() ? v.charAt(i) : '\0';
            if (Character.isDigit(c)) {
                cur.append(c);
            } else {
                if (cur.length() > 0) {
                    try {
                        nums.add(Integer.parseInt(cur.toString()));
                    } catch (NumberFormatException e) {
                        break;
                    }
                    cur.setLength(0);
                }
                if (c != '.') {
                    break;
                }
            }
        }
        if (nums.isEmpty()) {
            return null;
        }
        int[] result = new int[nums.size()];
        for (int i = 0; i < nums.size(); i++) {
            result[i] = nums.get(i);
        }
        return result;
    }
}
