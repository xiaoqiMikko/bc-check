package io.mikko.bccheck;

/** 判定等级。顺序即优先级，报告按此排序。 */
public enum Severity {

    /** 命中了 4 条 CVSS critical 之一。 */
    CRITICAL("CRITICAL"),
    /** 命中了 CVE，但都不在那 4 条 critical 里。 */
    HIGH("HIGH"),
    /** 版本号取不到或解析不了，判定不可靠，需要人工确认。 */
    UNKNOWN("UNKNOWN"),
    /** 不受 2026 年这批 CVE 影响。 */
    OK("OK");

    private final String label;

    Severity(String label) {
        this.label = label;
    }

    public String label() {
        return label;
    }

    /** CI 是否该因此卡门禁。 */
    public boolean isActionable() {
        return this == CRITICAL || this == HIGH;
    }
}
