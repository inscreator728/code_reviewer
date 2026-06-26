import java.util.*;
public class ScanCheck {
    public static void main(String[] args) throws Exception {
        List<CyberScanPro.Finding> findings = CyberScanPro.analyzeFile("sample.java");
        System.out.println("findings=" + findings.size());
        for (CyberScanPro.Finding f : findings) {
            System.out.println(f.getSeverity() + " | " + f.getMessage());
        }
    }
}
