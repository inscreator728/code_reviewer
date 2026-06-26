import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Pattern;
import java.util.stream.Stream;
import javax.swing.*;
import javax.swing.plaf.basic.*;
import javax.swing.table.*;

/**
 * CyberScan Pro - Advanced Multi-Language Code Review & Vulnerability Scanner
 * Pure Java Swing version - Ultra Tech / Cyber Theme with Matrix Rain Background
 * Holographic Glass UI - Anime/Cyberpunk Themed Dialogs
 */
public class CyberScanPro extends JFrame {

    private static final Color THEME_BG = new Color(2, 8, 14);
    private static final Color THEME_SURFACE = new Color(6, 16, 24);
    private static final Color THEME_SURFACE_ALT = new Color(9, 22, 32);
    private static final Color THEME_BORDER = new Color(28, 72, 90);
    private static final Color THEME_ACCENT = new Color(72, 209, 204);
    private static final Color THEME_TEXT = new Color(236, 248, 255);
    private static final Color THEME_MUTED = new Color(132, 176, 196);
    private static final Color THEME_CRITICAL = new Color(255, 92, 122);
    private static final Color THEME_HIGH = new Color(255, 138, 91);
    private static final Color THEME_MEDIUM = new Color(255, 179, 71);
    private static final Color THEME_LOW = new Color(91, 192, 222);
    private static final Color THEME_SUCCESS = new Color(0, 255, 170);
    private static final Color THEME_HOLO_GLASS = new Color(72, 209, 204, 30);
    private static final Color THEME_HOLO_GLOW = new Color(0, 255, 200, 80);

    private static final Font LABEL_FONT = new Font("Segoe UI", Font.BOLD, 14);
    private static final Font SMALL_LABEL_FONT = new Font("Segoe UI", Font.BOLD, 12);
    private static final Font BODY_FONT = new Font("Segoe UI", Font.PLAIN, 13);
    private static final Font MONO_FONT = new Font("Consolas", Font.PLAIN, 12);
    private static final Font HOLO_FONT = new Font("Segoe UI", Font.BOLD, 28);
    private static final Font HOLO_SUB_FONT = new Font("Segoe UI", Font.PLAIN, 16);

    // ========================================================================
    // Core scanning logic
    // ========================================================================

    private static final Set<String> EXCLUDED_DIRS = Set.of(
            ".git", ".svn", ".hg", "__pycache__", ".venv", "venv", "node_modules",
            "vendor", "dist", "build", "uploads", "cache", "tmp", "temp"
    );

    private static final Map<String, LanguageRules> LANGUAGE_RULES = new HashMap<>();

    static {
        // Python
        List<Rule> pythonRules = Arrays.asList(
                new Rule("\\beval\\s*\\(", "Use of eval() can execute attacker-controlled code.", "critical", "vulnerability", "Replace eval() with safe parsing or explicit logic.", "Code injection"),
                new Rule("\\bexec\\s*\\(", "Use of exec() creates arbitrary code execution risk.", "critical", "vulnerability", "Avoid exec() and use safer alternatives.", "Code execution"),
                new Rule("\\bsubprocess\\.(call|Popen)\\s*\\(.*shell\\s*=\\s*True", "Shell=True enables command injection in subprocess calls.", "critical", "vulnerability", "Set shell=False and pass arguments safely.", "Command injection"),
                new Rule("\\bpickle\\.loads?\\s*\\(", "Unsafe deserialization with pickle can lead to code execution.", "critical", "vulnerability", "Use JSON or a safer serialization format.", "Deserialization"),
                new Rule("\\byaml\\.load\\s*\\(", "yaml.load() without SafeLoader can deserialize untrusted data unsafely.", "high", "vulnerability", "Use yaml.safe_load() or yaml.load(..., Loader=SafeLoader).", "Deserialization"),
                new Rule("DEBUG\\s*=\\s*True", "Debug mode is enabled in a likely production configuration.", "high", "vulnerability", "Set DEBUG=False in production and hide sensitive output.", "Configuration"),
                new Rule("SECRET_KEY\\s*=\\s*['\"].*['\"]", "A hardcoded secret key was detected.", "high", "vulnerability", "Move secrets to environment variables or a secure vault.", "Secret exposure"),
                new Rule("\\binput\\s*\\(", "The input() function is not suitable for untrusted runtime input in production.", "medium", "review", "Prefer explicit CLI parsing or validated user input.", "Input handling"),
                new Rule("except\\s*:", "A bare except clause can hide important faults.", "medium", "review", "Catch specific exceptions instead of broad exceptions.", "Error handling"),
                new Rule("#\\s*TODO", "A TODO comment was left in the codebase.", "low", "review", "Resolve or document the task before deployment.", "Maintainability")
        );
        LANGUAGE_RULES.put("Python", new LanguageRules(Set.of(".py"), pythonRules));

        // PHP
        List<Rule> phpRules = Arrays.asList(
                new Rule("\\beval\\s*\\(", "eval() in PHP enables code injection.", "critical", "vulnerability", "Remove eval() and use explicit code paths.", "Code injection"),
                new Rule("\\b(exec|system|shell_exec|passthru|popen|proc_open)\\s*\\(", "Command execution via shell functions is risky.", "critical", "vulnerability", "Avoid shell execution on user-controlled input.", "Command injection"),
                new Rule("\\bmysql_query\\s*\\(", "Deprecated mysql_* functions are insecure and not supported in modern PHP.", "high", "vulnerability", "Migrate to PDO or mysqli with prepared statements.", "Database security"),
                new Rule("\\$_(?:GET|POST|REQUEST|COOKIE)\\b.*\\b(query|SELECT|UPDATE|DELETE|INSERT)", "User-controlled data appears in a SQL statement.", "critical", "vulnerability", "Use prepared statements and bind variables.", "SQL injection"),
                new Rule("\\b(include|include_once|require|require_once)\\s*\\(.*\\$", "Dynamic include paths may allow local or remote file inclusion.", "critical", "vulnerability", "Restrict includes to a strict whitelist of safe files.", "File inclusion"),
                new Rule("error_reporting\\s*\\(0\\)", "Error reporting is disabled, which can hide deployment issues.", "medium", "review", "Keep error reporting enabled in development and log issues carefully in production.", "Observability")
        );
        LANGUAGE_RULES.put("PHP", new LanguageRules(Set.of(".php", ".phtml"), phpRules));

        // JavaScript
        List<Rule> jsRules = Arrays.asList(
                new Rule("\\beval\\s*\\(", "eval() can execute arbitrary code from strings.", "critical", "vulnerability", "Avoid eval() and prefer structured data handling.", "Code injection"),
                new Rule("\\.innerHTML\\s*=", "Assigning to innerHTML can expose the app to XSS.", "high", "vulnerability", "Use textContent or DOM APIs instead of innerHTML.", "Cross-site scripting"),
                new Rule("\\bdocument\\.write\\s*\\(", "document.write() is unsafe for dynamic content injection.", "medium", "vulnerability", "Prefer DOM manipulation libraries or safe insertion methods.", "Cross-site scripting"),
                new Rule("console\\.log\\s*\\(", "A console.log() statement was left in the code.", "low", "review", "Remove debug logging before shipping production code.", "Maintainability")
        );
        LANGUAGE_RULES.put("JavaScript", new LanguageRules(Set.of(".js", ".mjs"), jsRules));

        // Java
        List<Rule> javaRules = Arrays.asList(
                new Rule("Runtime\\.getRuntime\\(\\)\\.exec", "Runtime.exec() allows command execution with possible injection risk.", "critical", "vulnerability", "Validate input and avoid direct command execution.", "Command injection"),
                new Rule("Statement\\s+.*=\\s*\".*\\+", "SQL text appears to be built via string concatenation.", "high", "vulnerability", "Use PreparedStatement and parameterized queries.", "SQL injection"),
                new Rule("catch\\s*\\(\\s*Exception\\s+\\w+\\s*\\)\\s*\\{\\s*\\}", "An empty catch block can swallow important failures.", "medium", "review", "Log the exception or handle it explicitly.", "Error handling")
        );
        LANGUAGE_RULES.put("Java", new LanguageRules(Set.of(".java"), javaRules));

        // C/C++
        List<Rule> cRules = Arrays.asList(
                new Rule("\\bgets\\s*\\(", "gets() is unsafe and can overflow the destination buffer.", "critical", "vulnerability", "Use fgets() or a bounded input function.", "Buffer overflow"),
                new Rule("\\bstrcpy\\s*\\(", "strcpy() is unsafe because it does not check bounds.", "critical", "vulnerability", "Use strncpy(), snprintf(), or std::string.", "Buffer overflow"),
                new Rule("\\bsprintf\\s*\\(", "sprintf() may overflow the destination buffer.", "high", "vulnerability", "Prefer snprintf() or bounded APIs.", "Buffer overflow"),
                new Rule("\\bsystem\\s*\\(", "Calling system() exposes command injection risks.", "high", "vulnerability", "Avoid shell execution and prefer direct APIs.", "Command injection")
        );
        LANGUAGE_RULES.put("C/C++", new LanguageRules(Set.of(".c", ".h", ".cpp", ".cc", ".hpp", ".cxx", ".hxx"), cRules));

        // HTML
        List<Rule> htmlRules = Arrays.asList(
                new Rule("on\\w+\\s*=\\s*['\"]", "Inline event handlers can weaken CSP protections.", "medium", "vulnerability", "Move behavior to external scripts and sanitize inputs.", "Client-side security"),
                new Rule("<script\\s+src", "An external script tag was detected; trust and integrity should be verified.", "medium", "review", "Use SRI and only include trusted scripts.", "Supply chain"),
                new Rule("<!--\\s*TODO", "A TODO comment is present in HTML.", "low", "review", "Resolve or document outstanding work.", "Maintainability")
        );
        LANGUAGE_RULES.put("HTML", new LanguageRules(Set.of(".html", ".htm"), htmlRules));

        // CSS
        List<Rule> cssRules = Arrays.asList(
                new Rule("expression\\s*\\(", "CSS expressions are obsolete and risky in legacy browsers.", "medium", "vulnerability", "Avoid expression() and use modern CSS techniques.", "Legacy security"),
                new Rule("!important", "!important is used heavily; this can make styling harder to maintain.", "low", "review", "Use it sparingly and refactor when possible.", "Maintainability")
        );
        LANGUAGE_RULES.put("CSS", new LanguageRules(Set.of(".css"), cssRules));
    }

    static class Rule {
        final String pattern;
        final String message;
        final String severity;
        final String type;
        final String recommendation;
        final String category;

        Rule(String pattern, String message, String severity, String type, String recommendation, String category) {
            this.pattern = pattern;
            this.message = message;
            this.severity = severity;
            this.type = type;
            this.recommendation = recommendation;
            this.category = category;
        }
    }

    static class LanguageRules {
        final Set<String> extensions;
        final List<Rule> rules;

        LanguageRules(Set<String> extensions, List<Rule> rules) {
            this.extensions = extensions;
            this.rules = rules;
        }
    }

    // Finding class (simple POJO)
    public static class Finding {
        private String file;
        private int line;
        private String severity;
        private String message;
        private String language;
        private String category;
        private String recommendation;
        private int confidence;
        private String type;

        public Finding(String file, int line, String severity, String message, String language,
                       String category, String recommendation, int confidence, String type) {
            this.file = file;
            this.line = line;
            this.severity = severity;
            this.message = message;
            this.language = language;
            this.category = category;
            this.recommendation = recommendation;
            this.confidence = confidence;
            this.type = type;
        }

        public String getFile() { return file; }
        public int getLine() { return line; }
        public String getSeverity() { return severity; }
        public String getMessage() { return message; }
        public String getLanguage() { return language; }
        public String getCategory() { return category; }
        public String getRecommendation() { return recommendation; }
        public int getConfidence() { return confidence; }
        public String getType() { return type; }
    }

    // Utility functions
    private static String detectLanguage(String filePath, String content) {
        String ext = "";
        int dot = filePath.lastIndexOf('.');
        if (dot > 0) {
            ext = filePath.substring(dot).toLowerCase();
        }

        switch (ext) {
            case ".py": return "Python";
            case ".php": case ".phtml": return "PHP";
            case ".java": return "Java";
            case ".js": case ".mjs": return "JavaScript";
            case ".c": case ".h": case ".cpp": case ".cc": case ".hpp": case ".cxx": case ".hxx": return "C/C++";
            case ".html": case ".htm": return "HTML";
            case ".css": return "CSS";
            default: break;
        }

        String lowerContent = content.toLowerCase();
        if (lowerContent.contains("<?php") || lowerContent.contains("<?=")) return "PHP";
        if (lowerContent.contains("<script") || lowerContent.contains("</html")) return "HTML";
        return "Unknown";
    }

    private static String normalizeSeverity(String severity) {
        switch (severity.toLowerCase()) {
            case "critical": case "error": return "critical";
            case "high": return "high";
            case "medium": case "warning": return "medium";
            case "low": case "info": return "low";
            default: return "low";
        }
    }

    private static String smartRecommendation(String message, String language) {
        String msg = message.toLowerCase();
        if (msg.contains("eval") || msg.contains("exec")) return "Replace dynamic execution with explicit logic and validated input.";
        if (msg.contains("sql")) return "Use parameterized queries and avoid concatenating user input.";
        if (msg.contains("xss") || msg.contains("innerhtml")) return "Escape or sanitize all user-controlled output before rendering it.";
        if (msg.contains("secret") || msg.contains("key")) return "Move secrets into environment variables or a dedicated secrets manager.";
        if (msg.contains("command") || msg.contains("shell")) return "Avoid passing untrusted input into shell commands.";
        if ("Python".equals(language) && msg.contains("debug")) return "Disable debug mode in production and log safely.";
        return "Review the context and apply the least-privilege fix.";
    }

    public static List<Finding> analyzeFile(String filePath) {
        List<Finding> issues = new ArrayList<>();
        String content;
        try {
            content = new String(Files.readAllBytes(Paths.get(filePath)), StandardCharsets.UTF_8);
        } catch (IOException e) {
            Finding err = new Finding(filePath, 0, "critical", "Could not read file: " + e.getMessage(),
                    detectLanguage(filePath, ""), "File access",
                    "Confirm file readability and permissions.", 95, "error");
            issues.add(err);
            return issues;
        }

        String language = detectLanguage(filePath, content);
        if ("Unknown".equals(language)) return issues;

        String[] lines = content.split("\\R");
        LanguageRules langRules = LANGUAGE_RULES.get(language);
        if (langRules == null) return issues;

        for (Rule rule : langRules.rules) {
            Pattern pattern = Pattern.compile(rule.pattern, Pattern.CASE_INSENSITIVE);
            for (int i = 0; i < lines.length; i++) {
                String line = lines[i];
                if (pattern.matcher(line).find()) {
                    String sev = normalizeSeverity(rule.severity);
                    int confidence = sev.equals("critical") || sev.equals("high") ? 90 : 75;
                    if (line.contains("$_") || line.toLowerCase().contains("request") || line.toLowerCase().contains("user"))
                        confidence += 5;
                    if (line.contains("TODO")) confidence = Math.max(60, confidence - 10);
                    String recommendation = rule.recommendation != null ? rule.recommendation : smartRecommendation(rule.message, language);
                    Finding f = new Finding(filePath, i + 1, sev, rule.message, language,
                            rule.category, recommendation, confidence, rule.type);
                    issues.add(f);
                }
            }
        }

        if ("Python".equals(language)) {
            Pattern cmdPattern = Pattern.compile("\\b(os|subprocess)\\.(system|popen|call|Popen)\\s*\\(");
            if (cmdPattern.matcher(content).find()) {
                Finding f = new Finding(filePath, 1, "high",
                        "Command execution helpers were found; verify arguments and shell usage.",
                        language, "Command execution",
                        "Avoid shell execution on untrusted input and prefer structured APIs.",
                        82, "vulnerability");
                issues.add(f);
            }
        }

        Set<String> seen = new HashSet<>();
        List<Finding> deduped = new ArrayList<>();
        for (Finding f : issues) {
            String key = f.getFile() + "|" + f.getLine() + "|" + f.getMessage() + "|" + f.getType();
            if (seen.add(key)) deduped.add(f);
        }
        return deduped;
    }

    // ========================================================================
    // Holographic Glass Dialog - Anime/Cyberpunk Themed
    // ========================================================================

    private static class HolographicDialog extends JDialog {
        private final String titleText;
        private final String messageText;
        private final String type; // "SUCCESS", "WARNING", "ERROR", "INFO"
        private final List<HoloParticle> particles = new ArrayList<>();
        private javax.swing.Timer animTimer;
        private float glowIntensity = 0.0f;
        private boolean glowUp = true;
        private float scanLineOffset = 0;

        private static class HoloParticle {
            float x, y, vx, vy, size, alpha;
            HoloParticle(float x, float y, float vx, float vy, float size, float alpha) {
                this.x = x; this.y = y; this.vx = vx; this.vy = vy; this.size = size; this.alpha = alpha;
            }
        }

        public HolographicDialog(JFrame parent, String title, String message, String type) {
            super(parent, true);
            this.titleText = title;
            this.messageText = message;
            this.type = type;
            setUndecorated(true);
            setBackground(new Color(0, 0, 0, 0));

            int w = 700;
            int h = 450;
            setSize(w, h);
            setLocationRelativeTo(parent);

            // Init particles
            Random rand = new Random();
            for (int i = 0; i < 60; i++) {
                particles.add(new HoloParticle(
                    rand.nextFloat() * w, rand.nextFloat() * h,
                    (rand.nextFloat() - 0.5f) * 2, (rand.nextFloat() - 0.5f) * 2,
                    1 + rand.nextFloat() * 3, 0.1f + rand.nextFloat() * 0.5f
                ));
            }

            JPanel glassPanel = new JPanel() {
                @Override
                protected void paintComponent(Graphics g) {
                    Graphics2D g2d = (Graphics2D) g.create();
                    g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
                    g2d.setRenderingHint(RenderingHints.KEY_TEXT_ANTIALIASING, RenderingHints.VALUE_TEXT_ANTIALIAS_ON);

                    int w = getWidth();
                    int h = getHeight();

                    // Dark glass background
                    g2d.setColor(new Color(2, 8, 14, 220));
                    g2d.fillRoundRect(0, 0, w, h, 30, 30);

                    // Glowing border
                    Color glowColor;
                    switch (type) {
                        case "SUCCESS": glowColor = THEME_SUCCESS; break;
                        case "WARNING": glowColor = THEME_MEDIUM; break;
                        case "ERROR": glowColor = THEME_CRITICAL; break;
                        default: glowColor = THEME_ACCENT; break;
                    }

                    // Outer glow
                    for (int i = 5; i > 0; i--) {
                        int alpha = (int)(glowIntensity * 30 / i);
                        g2d.setColor(new Color(glowColor.getRed(), glowColor.getGreen(), glowColor.getBlue(), alpha));
                        g2d.setStroke(new BasicStroke(i * 1.5f));
                        g2d.drawRoundRect(i, i, w - i * 2, h - i * 2, 30, 30);
                    }

                    // Inner border
                    g2d.setColor(new Color(glowColor.getRed(), glowColor.getGreen(), glowColor.getBlue(), 150));
                    g2d.setStroke(new BasicStroke(2));
                    g2d.drawRoundRect(2, 2, w - 4, h - 4, 28, 28);

                    // Scan lines
                    g2d.setClip(new Rectangle(0, 0, w, h));
                    scanLineOffset = (scanLineOffset + 2) % 8;
                    g2d.setColor(new Color(72, 209, 204, 15));
                    for (float y = scanLineOffset; y < h; y += 8) {
                        g2d.drawLine(0, (int)y, w, (int)y);
                    }
                    g2d.setClip(null);

                    // Particles
                    for (HoloParticle p : particles) {
                        g2d.setColor(new Color(glowColor.getRed(), glowColor.getGreen(), glowColor.getBlue(), (int)(p.alpha * 255)));
                        g2d.fillOval((int)(p.x - p.size/2), (int)(p.y - p.size/2), (int)p.size, (int)p.size);
                    }

                    // Icon
                    String icon;
                    Color iconColor;
                    switch (type) {
                        case "SUCCESS": icon = "✦"; iconColor = THEME_SUCCESS; break;
                        case "WARNING": icon = "⚠"; iconColor = THEME_MEDIUM; break;
                        case "ERROR": icon = "✖"; iconColor = THEME_CRITICAL; break;
                        default: icon = "ℹ"; iconColor = THEME_ACCENT; break;
                    }

                    g2d.setFont(new Font("Segoe UI", Font.PLAIN, 60));
                    g2d.setColor(new Color(iconColor.getRed(), iconColor.getGreen(), iconColor.getBlue(), 60));
                    String iconStr = icon;
                    FontMetrics fm = g2d.getFontMetrics();
                    int iconX = w/2 - fm.stringWidth(iconStr)/2;
                    int iconY = h/2 - 20;
                    g2d.drawString(iconStr, iconX, iconY);

                    // Title
                    g2d.setFont(HOLO_FONT);
                    fm = g2d.getFontMetrics();
                    g2d.setColor(glowColor);
                    int tx = w/2 - fm.stringWidth(titleText)/2;
                    g2d.drawString(titleText, tx, 80);

                    // Title glow
                    g2d.setFont(new Font("Segoe UI", Font.BOLD, 30));
                    fm = g2d.getFontMetrics();
                    g2d.setColor(new Color(glowColor.getRed(), glowColor.getGreen(), glowColor.getBlue(), 40));
                    g2d.drawString(titleText, tx + 2, 82);

                    // Message
                    g2d.setFont(HOLO_SUB_FONT);
                    fm = g2d.getFontMetrics();
                    g2d.setColor(THEME_TEXT);
                    String[] msgLines = messageText.split("\n");
                    int lineY = 140;
                    for (String line : msgLines) {
                        int mx = w/2 - fm.stringWidth(line)/2;
                        g2d.drawString(line, mx, lineY);
                        lineY += 30;
                    }

                    // Subtitle
                    g2d.setFont(new Font("Segoe UI", Font.ITALIC, 12));
                    g2d.setColor(THEME_MUTED);
                    String sub = "◆ CYBER SCAN PROTOCOL v3.0 ◆";
                    fm = g2d.getFontMetrics();
                    g2d.drawString(sub, w/2 - fm.stringWidth(sub)/2, h - 30);

                    g2d.dispose();
                }
            };
            glassPanel.setOpaque(false);
            setContentPane(glassPanel);

            // Animation timer
            animTimer = new javax.swing.Timer(30, e -> {
                Random r = new Random();
                for (HoloParticle p : particles) {
                    p.x += p.vx;
                    p.y += p.vy;
                    if (p.x < 0 || p.x > w) p.vx *= -1;
                    if (p.y < 0 || p.y > h) p.vy *= -1;
                    p.alpha = 0.1f + r.nextFloat() * 0.4f;
                }
                if (glowUp) {
                    glowIntensity += 0.03f;
                    if (glowIntensity >= 1.0f) glowUp = false;
                } else {
                    glowIntensity -= 0.03f;
                    if (glowIntensity <= 0.3f) glowUp = true;
                }
                repaint();
            });
            animTimer.start();

            // Click to dismiss
            addMouseListener(new MouseAdapter() {
                @Override
                public void mouseClicked(MouseEvent e) {
                    dispose();
                }
            });

            // Auto dismiss after 5 seconds
            new javax.swing.Timer(5000, e -> {
                if (isVisible()) dispose();
            }).start();
        }

        @Override
        public void dispose() {
            if (animTimer != null) animTimer.stop();
            super.dispose();
        }
    }

    // ========================================================================
    // Swing Application
    // ========================================================================

    private JTable findingsTable;
    private DefaultTableModel tableModel;
    private JTextArea detailArea;
    private JTextArea codePreviewArea;
    private JLabel statusLabel;
    private JProgressBar progressBar;
    private JLabel progressText;
    private JLabel fileCountLabel;

    private File targetFolder;
    private volatile boolean scanning = false;
    private volatile boolean stopScan = false;

    private JLabel totalLabel, criticalLabel, highLabel, mediumLabel, lowLabel;
    private JPanel barChartPanel;

    private List<Finding> allFindings = new ArrayList<>();
    private List<Finding> filteredFindings = new ArrayList<>();

    private JTextField searchField;
    private JComboBox<String> severityCombo;
    private JComboBox<String> languageCombo;

    private JButton browseBtn, scanBtn, stopBtn, exportBtn;

    public CyberScanPro() {
        setTitle("🛡️ CYBER SCAN PROTOCOL v3.0 - J.A.R.V.I.S.");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setMinimumSize(new Dimension(1200, 800));
        setExtendedState(JFrame.MAXIMIZED_BOTH);
        // Set application logo
        try {
            ImageIcon logoIcon = new ImageIcon(getClass().getResource("logo.png"));
            setIconImage(logoIcon.getImage());
        } catch (Exception e) {}

        // Set dark look and feel - NO LIGHT COLORS ALLOWED
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            UIManager.put("control", THEME_SURFACE);
            UIManager.put("Panel.background", THEME_BG);
            UIManager.put("Label.foreground", THEME_TEXT);
            UIManager.put("TextField.background", THEME_SURFACE_ALT);
            UIManager.put("TextField.foreground", THEME_TEXT);
            UIManager.put("TextField.caretForeground", THEME_ACCENT);
            UIManager.put("TextField.selectionBackground", new Color(12, 30, 42));
            UIManager.put("TextField.selectionForeground", THEME_TEXT);
            UIManager.put("TextArea.background", THEME_SURFACE_ALT);
            UIManager.put("TextArea.foreground", THEME_TEXT);
            UIManager.put("TextArea.selectionBackground", new Color(12, 30, 42));
            UIManager.put("TextArea.selectionForeground", THEME_TEXT);
            UIManager.put("ComboBox.background", THEME_SURFACE_ALT);
            UIManager.put("ComboBox.foreground", THEME_TEXT);
            UIManager.put("ComboBox.selectionBackground", THEME_SURFACE);
            UIManager.put("ComboBox.selectionForeground", THEME_ACCENT);
            UIManager.put("ComboBox.disabledBackground", THEME_SURFACE);
            UIManager.put("ComboBox.disabledForeground", THEME_MUTED);
            UIManager.put("Button.background", THEME_SURFACE);
            UIManager.put("Button.foreground", THEME_TEXT);
            UIManager.put("Button.select", THEME_SURFACE_ALT);
            UIManager.put("Button.disabledText", THEME_MUTED);
            UIManager.put("ToggleButton.background", THEME_SURFACE);
            UIManager.put("ToggleButton.foreground", THEME_TEXT);
            UIManager.put("TabbedPane.background", THEME_BG);
            UIManager.put("TabbedPane.foreground", THEME_TEXT);
            UIManager.put("TabbedPane.selected", THEME_SURFACE);
            UIManager.put("TabbedPane.unselectedBackground", THEME_SURFACE_ALT);
            UIManager.put("TabbedPane.contentAreaColor", THEME_BG);
            UIManager.put("TabbedPane.tabAreaBackground", THEME_BG);
            UIManager.put("TabbedPane.selectedForeground", THEME_TEXT);
            UIManager.put("TabbedPane.highlight", THEME_BORDER);
            UIManager.put("TabbedPane.darkShadow", THEME_BORDER);
            UIManager.put("TabbedPane.shadow", THEME_BORDER);
            UIManager.put("TabbedPane.lightHighlight", THEME_BORDER);
            UIManager.put("TabbedPane.focus", THEME_ACCENT);
            UIManager.put("ScrollBar.background", THEME_SURFACE);
            UIManager.put("ScrollBar.foreground", THEME_BORDER);
            UIManager.put("ScrollBar.track", THEME_SURFACE);
            UIManager.put("ScrollBar.thumb", THEME_BORDER);
            UIManager.put("ScrollBar.thumbHighlight", THEME_ACCENT);
            UIManager.put("ScrollBar.thumbDarkShadow", THEME_BORDER);
            UIManager.put("Separator.foreground", THEME_BORDER);
            UIManager.put("MenuBar.background", THEME_BG);
            UIManager.put("Menu.background", THEME_SURFACE);
            UIManager.put("Menu.foreground", THEME_TEXT);
            UIManager.put("Menu.selectionBackground", THEME_SURFACE_ALT);
            UIManager.put("Menu.selectionForeground", THEME_ACCENT);
            UIManager.put("MenuItem.background", THEME_SURFACE);
            UIManager.put("MenuItem.foreground", THEME_TEXT);
            UIManager.put("MenuItem.selectionBackground", THEME_SURFACE_ALT);
            UIManager.put("MenuItem.selectionForeground", THEME_ACCENT);
            UIManager.put("PopupMenu.background", THEME_SURFACE);
            UIManager.put("PopupMenu.foreground", THEME_TEXT);
            UIManager.put("ToolTip.background", THEME_SURFACE);
            UIManager.put("ToolTip.foreground", THEME_TEXT);
            UIManager.put("OptionPane.background", THEME_BG);
            UIManager.put("OptionPane.foreground", THEME_TEXT);
            UIManager.put("OptionPane.messageForeground", THEME_TEXT);
            UIManager.put("OptionPane.buttonBackground", THEME_SURFACE);
            UIManager.put("OptionPane.buttonForeground", THEME_TEXT);
            UIManager.put("FileChooser.background", THEME_BG);
            UIManager.put("FileChooser.foreground", THEME_TEXT);
            UIManager.put("List.background", THEME_SURFACE_ALT);
            UIManager.put("List.foreground", THEME_TEXT);
            UIManager.put("List.selectionBackground", THEME_SURFACE);
            UIManager.put("List.selectionForeground", THEME_ACCENT);
            UIManager.put("Table.background", THEME_SURFACE_ALT);
            UIManager.put("Table.foreground", THEME_TEXT);
            UIManager.put("Table.selectionBackground", new Color(12, 30, 42));
            UIManager.put("Table.selectionForeground", THEME_TEXT);
            UIManager.put("Table.gridColor", THEME_BORDER);
            UIManager.put("TableHeader.background", new Color(6, 18, 26));
            UIManager.put("TableHeader.foreground", THEME_ACCENT);
            UIManager.put("ProgressBar.background", THEME_SURFACE);
            UIManager.put("ProgressBar.foreground", THEME_ACCENT);
            UIManager.put("ProgressBar.selectionBackground", THEME_BG);
            UIManager.put("ProgressBar.selectionForeground", THEME_TEXT);
            UIManager.put("Viewport.background", THEME_SURFACE_ALT);
            UIManager.put("Viewport.foreground", THEME_TEXT);
            UIManager.put("EditorPane.background", THEME_SURFACE_ALT);
            UIManager.put("EditorPane.foreground", THEME_TEXT);
            UIManager.put("TextPane.background", THEME_SURFACE_ALT);
            UIManager.put("TextPane.foreground", THEME_TEXT);
            UIManager.put("PasswordField.background", THEME_SURFACE_ALT);
            UIManager.put("PasswordField.foreground", THEME_TEXT);
            UIManager.put("ScrollPane.background", THEME_BG);
            UIManager.put("ScrollPane.foreground", THEME_TEXT);
            UIManager.put("SplitPane.background", THEME_BG);
            UIManager.put("SplitPane.foreground", THEME_BORDER);
            UIManager.put("SplitPane.dividerSize", 2);
            UIManager.put("ToolBar.background", THEME_BG);
            UIManager.put("ToolBar.foreground", THEME_TEXT);
            UIManager.put("Tree.background", THEME_SURFACE_ALT);
            UIManager.put("Tree.foreground", THEME_TEXT);
            UIManager.put("Tree.selectionBackground", THEME_SURFACE);
            UIManager.put("Tree.selectionForeground", THEME_ACCENT);
            UIManager.put("Tree.textBackground", THEME_SURFACE_ALT);
            UIManager.put("Tree.textForeground", THEME_TEXT);
            UIManager.put("InternalFrame.background", THEME_BG);
            UIManager.put("Desktop.background", THEME_BG);
            UIManager.put("defaultFont", BODY_FONT);
            UIManager.put("Button.font", new Font("Segoe UI", Font.BOLD, 13));
            UIManager.put("Label.font", LABEL_FONT);
            UIManager.put("TextField.font", BODY_FONT);
            UIManager.put("TextArea.font", BODY_FONT);
            UIManager.put("ComboBox.font", BODY_FONT);
            UIManager.put("Table.font", BODY_FONT);
            UIManager.put("TableHeader.font", new Font("Segoe UI", Font.BOLD, 13));
        } catch (Exception e) {}

        // Main panel with Matrix rain background
        MatrixRainPanel matrixPanel = new MatrixRainPanel();
        matrixPanel.setLayout(new BorderLayout());
        matrixPanel.setOpaque(true);

        // UI container
        JPanel uiContainer = new JPanel(new BorderLayout(10, 10));
        uiContainer.setOpaque(false);
        uiContainer.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        buildToolbar(uiContainer);
        buildMainContent(uiContainer);
        buildStatusBar(uiContainer);

        matrixPanel.add(uiContainer, BorderLayout.CENTER);
        setContentPane(matrixPanel);

        matrixPanel.startAnimation();

        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                matrixPanel.stopAnimation();
            }
        });

        setVisible(true);
    }

    private void buildToolbar(JPanel parent) {
        JToolBar toolbar = new JToolBar();
        toolbar.setFloatable(false);
        toolbar.setBackground(THEME_BG);
        toolbar.setBorder(BorderFactory.createMatteBorder(0, 0, 1, 0, THEME_BORDER));
        toolbar.setBorderPainted(true);

        browseBtn = createStyledButton("📁 Browse", THEME_SURFACE);
        browseBtn.setToolTipText("Select a directory to scan");
        browseBtn.addActionListener(e -> browseFolder());

        scanBtn = createStyledButton("▶ Scan", THEME_SURFACE_ALT);
        scanBtn.setToolTipText("Start scanning the selected directory");
        scanBtn.addActionListener(e -> startScan());

        stopBtn = createStyledButton("⏹ Abort", THEME_SURFACE);
        stopBtn.setEnabled(false);
        stopBtn.setToolTipText("Stop the ongoing scan");
        stopBtn.addActionListener(e -> stopScan());

        exportBtn = createStyledButton("📄 Export HTML", THEME_SURFACE);
        exportBtn.setEnabled(false);
        exportBtn.setToolTipText("Export findings as an HTML report");
        exportBtn.addActionListener(e -> exportHtml());

        JButton fullscreenBtn = createStyledButton("⛶ Full Screen", THEME_SURFACE);
        fullscreenBtn.setToolTipText("Toggle full screen mode");
        fullscreenBtn.addActionListener(e -> toggleFullScreen());

        JLabel targetLabel = new JLabel("Target:");
        targetLabel.setForeground(THEME_ACCENT);
        targetLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));

        JLabel selectedFolderLabel = new JLabel("Not selected");
        selectedFolderLabel.setForeground(THEME_MUTED);
        selectedFolderLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));

        fileCountLabel = new JLabel("Files: 0");
        fileCountLabel.setForeground(THEME_MUTED);
        fileCountLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));

        toolbar.add(browseBtn);
        toolbar.add(scanBtn);
        toolbar.add(stopBtn);
        toolbar.add(exportBtn);
        toolbar.addSeparator();
        toolbar.add(fullscreenBtn);
        toolbar.addSeparator();
        toolbar.add(targetLabel);
        toolbar.add(selectedFolderLabel);
        toolbar.add(Box.createHorizontalGlue());
        toolbar.add(fileCountLabel);

        parent.add(toolbar, BorderLayout.NORTH);
        this.folderLabel = selectedFolderLabel;
    }

    private JButton createStyledButton(String text, Color bg) {
        JButton btn = new JButton(text);
        btn.setFocusPainted(false);
        btn.setBackground(bg);
        btn.setForeground(THEME_TEXT);
        btn.setFont(new Font("Segoe UI", Font.BOLD, 13));
        btn.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(THEME_BORDER, 1),
                BorderFactory.createEmptyBorder(7, 12, 7, 12)
        ));
        // Remove hover light effects - keep dark always
        btn.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                btn.setBackground(THEME_SURFACE_ALT);
            }
            @Override
            public void mouseExited(MouseEvent e) {
                btn.setBackground(bg);
            }
        });
        return btn;
    }

    private JLabel folderLabel;

    private void buildMainContent(JPanel parent) {
        JSplitPane splitPane = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT);
        splitPane.setOpaque(false);
        splitPane.setBorder(null);
        splitPane.setDividerSize(2);
        splitPane.setDividerLocation(0.6);
        // Dark divider
        splitPane.setUI(new BasicSplitPaneUI() {
            @Override
            public void paint(Graphics g, JComponent jc) {
                g.setColor(THEME_BORDER);
                g.fillRect(0, 0, getSize().width, getSize().height);
            }
        });

        // Left panel: findings table with filters
        JPanel leftPanel = new JPanel(new BorderLayout(5, 5));
        leftPanel.setOpaque(true);
        leftPanel.setBackground(THEME_BG);

        // Filters
        JPanel filterPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 5));
        filterPanel.setOpaque(true);
        filterPanel.setBackground(THEME_BG);
        filterPanel.setBorder(BorderFactory.createEmptyBorder(4, 0, 6, 0));

        searchField = new JTextField(15);
        searchField.setToolTipText("Search for text in findings");
        searchField.setBackground(THEME_SURFACE_ALT);
        searchField.setForeground(THEME_TEXT);
        searchField.setCaretColor(THEME_ACCENT);
        searchField.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(THEME_BORDER, 1),
                BorderFactory.createEmptyBorder(6, 10, 6, 10)
        ));
        searchField.setPreferredSize(new Dimension(220, 32));
        searchField.getDocument().addDocumentListener(new javax.swing.event.DocumentListener() {
            public void changedUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
            public void removeUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
            public void insertUpdate(javax.swing.event.DocumentEvent e) { applyFilters(); }
        });

        severityCombo = new JComboBox<>(new String[]{"All", "Critical", "High", "Medium", "Low"});
        severityCombo.setToolTipText("Filter by severity");
        severityCombo.setBackground(THEME_SURFACE_ALT);
        severityCombo.setForeground(THEME_TEXT);
        severityCombo.setPreferredSize(new Dimension(120, 32));
        severityCombo.addActionListener(e -> applyFilters());
        // Dark combo box popup
        severityCombo.setUI(new BasicComboBoxUI() {
            @Override
            protected JButton createArrowButton() {
                JButton btn = new JButton("▼");
                btn.setFont(new Font("Segoe UI", Font.BOLD, 10));
                btn.setForeground(THEME_ACCENT);
                btn.setBackground(THEME_SURFACE_ALT);
                btn.setBorder(BorderFactory.createLineBorder(THEME_BORDER));
                btn.setFocusPainted(false);
                return btn;
            }
        });

        languageCombo = new JComboBox<>();
        languageCombo.addItem("All");
        for (String lang : LANGUAGE_RULES.keySet()) languageCombo.addItem(lang);
        languageCombo.setToolTipText("Filter by programming language");
        languageCombo.setBackground(THEME_SURFACE_ALT);
        languageCombo.setForeground(THEME_TEXT);
        languageCombo.setPreferredSize(new Dimension(140, 32));
        languageCombo.addActionListener(e -> applyFilters());
        languageCombo.setUI(new BasicComboBoxUI() {
            @Override
            protected JButton createArrowButton() {
                JButton btn = new JButton("▼");
                btn.setFont(new Font("Segoe UI", Font.BOLD, 10));
                btn.setForeground(THEME_ACCENT);
                btn.setBackground(THEME_SURFACE_ALT);
                btn.setBorder(BorderFactory.createLineBorder(THEME_BORDER));
                btn.setFocusPainted(false);
                return btn;
            }
        });

        JLabel searchIcon = new JLabel("🔍");
        searchIcon.setForeground(THEME_ACCENT);
        searchIcon.setFont(new Font("Segoe UI", Font.BOLD, 14));
        JLabel severityLabel = new JLabel("Severity:");
        severityLabel.setForeground(THEME_TEXT);
        severityLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));
        JLabel languageLabel = new JLabel("Language:");
        languageLabel.setForeground(THEME_TEXT);
        languageLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));

        filterPanel.add(searchIcon);
        filterPanel.add(searchField);
        filterPanel.add(severityLabel);
        filterPanel.add(severityCombo);
        filterPanel.add(languageLabel);
        filterPanel.add(languageCombo);

        leftPanel.add(filterPanel, BorderLayout.NORTH);

        // Table
        String[] columns = {"File", "Line", "Severity", "Message", "Language", "Category", "Confidence"};
        tableModel = new DefaultTableModel(columns, 0) {
            @Override
            public boolean isCellEditable(int row, int col) { return false; }
        };
        findingsTable = new JTable(tableModel);
        findingsTable.setBackground(THEME_SURFACE_ALT);
        findingsTable.setForeground(THEME_TEXT);
        findingsTable.setGridColor(THEME_BORDER);
        findingsTable.setRowHeight(28);
        findingsTable.getTableHeader().setBackground(new Color(6, 18, 26));
        findingsTable.getTableHeader().setForeground(THEME_ACCENT);
        findingsTable.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 13));
        findingsTable.setSelectionBackground(new Color(12, 30, 42));
        findingsTable.setSelectionForeground(THEME_TEXT);
        findingsTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        findingsTable.setShowHorizontalLines(true);
        findingsTable.setShowVerticalLines(true);
        findingsTable.setIntercellSpacing(new Dimension(1, 1));

        // Dark table header renderer - no light hover
        findingsTable.getTableHeader().setDefaultRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                JLabel label = (JLabel) super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                label.setBackground(new Color(6, 18, 26));
                label.setForeground(THEME_ACCENT);
                label.setFont(new Font("Segoe UI", Font.BOLD, 13));
                label.setBorder(BorderFactory.createCompoundBorder(
                    BorderFactory.createMatteBorder(0, 0, 1, 1, THEME_BORDER),
                    BorderFactory.createEmptyBorder(4, 8, 4, 8)
                ));
                return label;
            }
        });

        // Set column widths
        findingsTable.getColumnModel().getColumn(0).setPreferredWidth(200);
        findingsTable.getColumnModel().getColumn(1).setPreferredWidth(60);
        findingsTable.getColumnModel().getColumn(2).setPreferredWidth(80);
        findingsTable.getColumnModel().getColumn(3).setPreferredWidth(300);
        findingsTable.getColumnModel().getColumn(4).setPreferredWidth(80);
        findingsTable.getColumnModel().getColumn(5).setPreferredWidth(120);
        findingsTable.getColumnModel().getColumn(6).setPreferredWidth(80);

        // Custom renderer for severity
        findingsTable.getColumnModel().getColumn(2).setCellRenderer(new DefaultTableCellRenderer() {
            @Override
            public Component getTableCellRendererComponent(JTable table, Object value, boolean isSelected, boolean hasFocus, int row, int column) {
                Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);
                if (value != null) {
                    String sev = value.toString().toLowerCase();
                    Color color;
                    switch (sev) {
                        case "critical": color = THEME_CRITICAL; break;
                        case "high": color = THEME_HIGH; break;
                        case "medium": color = THEME_MEDIUM; break;
                        case "low": color = THEME_LOW; break;
                        default: color = THEME_TEXT;
                    }
                    c.setForeground(color);
                    ((JLabel)c).setHorizontalAlignment(SwingConstants.CENTER);
                }
                return c;
            }
        });

        // Add click listener to show details
        findingsTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int row = findingsTable.getSelectedRow();
                if (row != -1) {
                    String file = (String) tableModel.getValueAt(row, 0);
                    int line = Integer.parseInt((String) tableModel.getValueAt(row, 1));
                    String message = (String) tableModel.getValueAt(row, 3);
                    for (Finding f : filteredFindings) {
                        if (f.getFile().equals(file) && f.getLine() == line && f.getMessage().equals(message)) {
                            showDetails(f);
                            break;
                        }
                    }
                }
            }
        });

        JScrollPane tableScroll = new JScrollPane(findingsTable);
        tableScroll.setOpaque(true);
        tableScroll.setBackground(THEME_BG);
        tableScroll.getViewport().setBackground(THEME_SURFACE_ALT);
        tableScroll.getViewport().setOpaque(true);
        tableScroll.setBorder(BorderFactory.createLineBorder(THEME_BORDER, 1));
        // Dark scroll pane corner
        tableScroll.setCorner(JScrollPane.LOWER_RIGHT_CORNER, new JPanel() {{
            setBackground(THEME_BG);
            setOpaque(true);
        }});
        leftPanel.add(tableScroll, BorderLayout.CENTER);

        // Right panel: Tabs
        JTabbedPane rightTabs = new JTabbedPane();
        rightTabs.setOpaque(true);
        rightTabs.setBackground(THEME_BG);
        rightTabs.setForeground(THEME_TEXT);
        rightTabs.setBorder(BorderFactory.createLineBorder(THEME_BORDER, 1));
        rightTabs.setFont(new Font("Segoe UI", Font.BOLD, 13));
        rightTabs.setTabLayoutPolicy(JTabbedPane.SCROLL_TAB_LAYOUT);

        // Force dark backgrounds on all tabs - NO LIGHT COLORS
        rightTabs.setUI(new BasicTabbedPaneUI() {
            @Override
            protected void paintTabBackground(Graphics g, int tabPlacement, int tabIndex, int x, int y, int w, int h, boolean isSelected) {
                g.setColor(isSelected ? THEME_SURFACE : THEME_SURFACE_ALT);
                g.fillRect(x, y, w, h);
            }
            @Override
            protected void paintTabBorder(Graphics g, int tabPlacement, int tabIndex, int x, int y, int w, int h, boolean isSelected) {
                g.setColor(THEME_BORDER);
                g.drawRect(x, y, w - 1, h - 1);
            }
            @Override
            protected void paintContentBorder(Graphics g, int tabPlacement, int selectedIndex) {
                int width = tabPane.getWidth();
                int height = tabPane.getHeight();
                Insets insets = tabPane.getInsets();
                int x = insets.left;
                int y = getTabAreaInsets(tabPlacement).top + 30;
                int w = width - insets.right - insets.left;
                int h = height - y - insets.bottom;
                g.setColor(THEME_BORDER);
                g.drawRect(x, y, w - 1, h - 1);
            }
            @Override
            protected void paintFocusIndicator(Graphics g, int tabPlacement, Rectangle[] rects, int tabIndex, Rectangle iconRect, Rectangle textRect, boolean isSelected) {
                // No focus indicator - keep dark
            }
        });

        // Details tab
        JPanel detailsPanel = new JPanel(new BorderLayout(5, 5));
        detailsPanel.setOpaque(true);
        detailsPanel.setBackground(THEME_BG);

        JLabel detailsLabel = new JLabel("Issue Details");
        detailsLabel.setForeground(THEME_ACCENT);
        detailsLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        detailsPanel.add(detailsLabel, BorderLayout.NORTH);

        detailArea = new JTextArea();
        detailArea.setEditable(false);
        detailArea.setBackground(THEME_SURFACE_ALT);
        detailArea.setForeground(THEME_TEXT);
        detailArea.setBorder(BorderFactory.createLineBorder(THEME_BORDER, 1));
        detailArea.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        detailArea.setWrapStyleWord(true);
        detailArea.setLineWrap(true);
        detailArea.setSelectionColor(new Color(12, 30, 42));
        detailArea.setSelectedTextColor(THEME_TEXT);
        JScrollPane detailScroll = new JScrollPane(detailArea);
        detailScroll.setOpaque(true);
        detailScroll.setBackground(THEME_BG);
        detailScroll.getViewport().setBackground(THEME_SURFACE_ALT);
        detailScroll.getViewport().setOpaque(true);
        detailScroll.setCorner(JScrollPane.LOWER_RIGHT_CORNER, new JPanel() {{
            setBackground(THEME_BG); setOpaque(true);
        }});
        detailsPanel.add(detailScroll, BorderLayout.CENTER);

        JLabel codeLabel = new JLabel("Code Preview");
        codeLabel.setForeground(THEME_ACCENT);
        codeLabel.setFont(new Font("Segoe UI", Font.BOLD, 15));
        detailsPanel.add(codeLabel, BorderLayout.SOUTH);

        codePreviewArea = new JTextArea();
        codePreviewArea.setEditable(false);
        codePreviewArea.setBackground(THEME_SURFACE_ALT);
        codePreviewArea.setForeground(THEME_TEXT);
        codePreviewArea.setBorder(BorderFactory.createLineBorder(THEME_BORDER, 1));
        codePreviewArea.setFont(MONO_FONT);
        codePreviewArea.setSelectionColor(new Color(12, 30, 42));
        codePreviewArea.setSelectedTextColor(THEME_TEXT);
        JScrollPane codeScroll = new JScrollPane(codePreviewArea);
        codeScroll.setOpaque(true);
        codeScroll.setBackground(THEME_BG);
        codeScroll.getViewport().setBackground(THEME_SURFACE_ALT);
        codeScroll.getViewport().setOpaque(true);
        codeScroll.setCorner(JScrollPane.LOWER_RIGHT_CORNER, new JPanel() {{
            setBackground(THEME_BG); setOpaque(true);
        }});
        detailsPanel.add(codeScroll, BorderLayout.SOUTH);

        rightTabs.addTab("🔍 Details", detailsPanel);

        // Language Stats tab
        JPanel statsPanel = new JPanel(new BorderLayout());
        statsPanel.setOpaque(true);
        statsPanel.setBackground(THEME_BG);
        JLabel statsLabel = new JLabel("Findings per Language & Severity");
        statsLabel.setForeground(THEME_ACCENT);
        statsLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        statsPanel.add(statsLabel, BorderLayout.NORTH);

        JTable statsTable = new JTable();
        statsTable.setBackground(THEME_SURFACE_ALT);
        statsTable.setForeground(THEME_TEXT);
        statsTable.setGridColor(THEME_BORDER);
        statsTable.setRowHeight(28);
        statsTable.getTableHeader().setBackground(new Color(6, 18, 26));
        statsTable.getTableHeader().setForeground(THEME_ACCENT);
        statsTable.getTableHeader().setFont(new Font("Segoe UI", Font.BOLD, 13));
        statsTable.setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        statsTable.setSelectionBackground(new Color(12, 30, 42));
        statsTable.setSelectionForeground(THEME_TEXT);
        JScrollPane statsScroll = new JScrollPane(statsTable);
        statsScroll.setOpaque(true);
        statsScroll.setBackground(THEME_BG);
        statsScroll.getViewport().setBackground(THEME_SURFACE_ALT);
        statsScroll.getViewport().setOpaque(true);
        statsScroll.setBorder(BorderFactory.createLineBorder(THEME_BORDER, 1));
        statsScroll.setCorner(JScrollPane.LOWER_RIGHT_CORNER, new JPanel() {{
            setBackground(THEME_BG); setOpaque(true);
        }});
        statsPanel.add(statsScroll, BorderLayout.CENTER);
        rightTabs.addTab("📊 Language Stats", statsPanel);

        // Dashboard tab
        JPanel dashboardPanel = new JPanel(new BorderLayout(10, 10));
        dashboardPanel.setOpaque(true);
        dashboardPanel.setBackground(THEME_BG);

        JLabel dashLabel = new JLabel("Dashboard");
        dashLabel.setForeground(THEME_ACCENT);
        dashLabel.setFont(new Font("Segoe UI", Font.BOLD, 16));
        dashboardPanel.add(dashLabel, BorderLayout.NORTH);

        JPanel cardPanel = new JPanel(new GridLayout(1, 5, 15, 0));
        cardPanel.setOpaque(true);
        cardPanel.setBackground(THEME_BG);
        totalLabel = createCard("Total", "0", "#7fffd4");
        criticalLabel = createCard("Critical", "0", "#ff5c7a");
        highLabel = createCard("High", "0", "#ff8a5b");
        mediumLabel = createCard("Medium", "0", "#ffb347");
        lowLabel = createCard("Low", "0", "#5bc0de");
        cardPanel.add(totalLabel);
        cardPanel.add(criticalLabel);
        cardPanel.add(highLabel);
        cardPanel.add(mediumLabel);
        cardPanel.add(lowLabel);
        dashboardPanel.add(cardPanel, BorderLayout.NORTH);

        JLabel chartTitle = new JLabel("Findings by Language");
        chartTitle.setForeground(THEME_ACCENT);
        chartTitle.setFont(new Font("Segoe UI", Font.BOLD, 14));
        dashboardPanel.add(chartTitle, BorderLayout.CENTER);

        barChartPanel = new JPanel() {
            @Override
            protected void paintComponent(Graphics g) {
                super.paintComponent(g);
                drawBarChart(g);
            }
        };
        barChartPanel.setBackground(THEME_SURFACE);
        barChartPanel.setBorder(BorderFactory.createLineBorder(THEME_BORDER, 1));
        barChartPanel.setPreferredSize(new Dimension(100, 200));
        dashboardPanel.add(barChartPanel, BorderLayout.SOUTH);

        rightTabs.addTab("📈 Dashboard", dashboardPanel);

        splitPane.setLeftComponent(leftPanel);
        splitPane.setRightComponent(rightTabs);

        parent.add(splitPane, BorderLayout.CENTER);
    }

    private JLabel createCard(String title, String value, String color) {
        JPanel card = new JPanel(new BorderLayout());
        card.setBackground(THEME_SURFACE);
        card.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(Color.decode(color), 1),
                BorderFactory.createEmptyBorder(12, 18, 12, 18)
        ));
        JLabel titleLabel = new JLabel(title, SwingConstants.CENTER);
        titleLabel.setForeground(THEME_MUTED);
        titleLabel.setFont(new Font("Segoe UI", Font.BOLD, 14));
        JLabel valueLabel = new JLabel(value, SwingConstants.CENTER);
        valueLabel.setForeground(Color.decode(color));
        valueLabel.setFont(new Font("Segoe UI", Font.BOLD, 30));
        card.add(titleLabel, BorderLayout.NORTH);
        card.add(valueLabel, BorderLayout.CENTER);
        return valueLabel;
    }

    private void buildStatusBar(JPanel parent) {
        JPanel statusBar = new JPanel(new BorderLayout(10, 0));
        statusBar.setBackground(THEME_BG);
        statusBar.setBorder(BorderFactory.createMatteBorder(1, 0, 0, 0, THEME_BORDER));
        statusBar.setOpaque(true);

        JPanel leftStatus = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        leftStatus.setOpaque(true);
        leftStatus.setBackground(THEME_BG);
        progressBar = new JProgressBar(0, 100);
        progressBar.setPreferredSize(new Dimension(200, 20));
        progressBar.setStringPainted(true);
        progressBar.setForeground(THEME_ACCENT);
        progressBar.setBackground(THEME_SURFACE);
        progressBar.setBorderPainted(true);
        progressBar.setBorder(BorderFactory.createLineBorder(THEME_BORDER));
        leftStatus.add(progressBar);

        progressText = new JLabel("Ready");
        progressText.setForeground(THEME_ACCENT);
        progressText.setFont(new Font("Segoe UI", Font.BOLD, 13));
        leftStatus.add(progressText);

        statusLabel = new JLabel("Welcome to CyberScan Pro");
        statusLabel.setForeground(THEME_ACCENT);
        statusLabel.setFont(new Font("Segoe UI", Font.BOLD, 13));
        statusLabel.setHorizontalAlignment(SwingConstants.RIGHT);

        statusBar.add(leftStatus, BorderLayout.WEST);
        statusBar.add(statusLabel, BorderLayout.EAST);

        parent.add(statusBar, BorderLayout.SOUTH);
    }

    private void updateDashboard() {
        int total = allFindings.size();
        Map<String, Integer> sevCounts = new HashMap<>();
        sevCounts.put("critical", 0);
        sevCounts.put("high", 0);
        sevCounts.put("medium", 0);
        sevCounts.put("low", 0);
        for (Finding f : allFindings) {
            sevCounts.merge(f.getSeverity().toLowerCase(), 1, Integer::sum);
        }
        totalLabel.setText(String.valueOf(total));
        criticalLabel.setText(String.valueOf(sevCounts.getOrDefault("critical", 0)));
        highLabel.setText(String.valueOf(sevCounts.getOrDefault("high", 0)));
        mediumLabel.setText(String.valueOf(sevCounts.getOrDefault("medium", 0)));
        lowLabel.setText(String.valueOf(sevCounts.getOrDefault("low", 0)));
        barChartPanel.repaint();
    }

    private void drawBarChart(Graphics g) {
        Graphics2D g2d = (Graphics2D) g;
        g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

        int width = barChartPanel.getWidth();
        int height = barChartPanel.getHeight();
        if (width <= 0 || height <= 0) return;

        Map<String, Integer> langCounts = new HashMap<>();
        for (Finding f : allFindings) {
            langCounts.merge(f.getLanguage(), 1, Integer::sum);
        }
        if (langCounts.isEmpty()) {
            g2d.setColor(THEME_TEXT);
            g2d.drawString("No data", width/2 - 30, height/2);
            return;
        }

        List<Map.Entry<String, Integer>> entries = new ArrayList<>(langCounts.entrySet());
        entries.sort((a, b) -> b.getValue().compareTo(a.getValue()));

        int topMargin = 20, bottomMargin = 30, leftMargin = 40, rightMargin = 20;
        int chartWidth = width - leftMargin - rightMargin;
        int chartHeight = height - topMargin - bottomMargin;
        if (chartWidth <= 0 || chartHeight <= 0) return;

        int maxVal = entries.stream().mapToInt(Map.Entry::getValue).max().orElse(1);
        double barSpacing = (double) chartWidth / entries.size();
        double barWidth = Math.min(50, barSpacing * 0.6);
        double xStart = leftMargin + (barSpacing - barWidth) / 2;

        String[] colors = {"#7fffd4", "#ff5c7a", "#ff8a5b", "#ffb347", "#5bc0de", "#a78bfa", "#f472b6", "#34d399"};

        for (int i = 0; i < entries.size(); i++) {
            String lang = entries.get(i).getKey();
            int count = entries.get(i).getValue();
            double barHeight = (count / (double) maxVal) * chartHeight;
            int y = (int) (height - bottomMargin - barHeight);

            g2d.setColor(Color.decode(colors[i % colors.length]));
            g2d.fillRect((int)(xStart + i * barSpacing), y, (int)barWidth, (int)barHeight);

            g2d.setColor(THEME_TEXT);
            g2d.setFont(new Font("Segoe UI", Font.BOLD, 10));
            String label = lang.length() > 4 ? lang.substring(0, 4) : lang;
            int labelWidth = g2d.getFontMetrics().stringWidth(label);
            g2d.drawString(label, (int)(xStart + i * barSpacing + barWidth/2 - labelWidth/2), height - bottomMargin + 15);

            String countStr = String.valueOf(count);
            int countWidth = g2d.getFontMetrics().stringWidth(countStr);
            g2d.setColor(THEME_ACCENT);
            g2d.drawString(countStr, (int)(xStart + i * barSpacing + barWidth/2 - countWidth/2), y - 5);
        }
    }

    private void applyFilters() {
        String search = searchField.getText().toLowerCase();
        String severity = (String) severityCombo.getSelectedItem();
        String language = (String) languageCombo.getSelectedItem();

        filteredFindings.clear();
        for (Finding f : allFindings) {
            boolean match = true;
            if (search != null && !search.isEmpty()) {
                if (!(f.getFile().toLowerCase().contains(search) ||
                        String.valueOf(f.getLine()).contains(search) ||
                        f.getMessage().toLowerCase().contains(search) ||
                        f.getCategory().toLowerCase().contains(search) ||
                        f.getLanguage().toLowerCase().contains(search))) {
                    match = false;
                }
            }
            if (match && severity != null && !severity.equals("All")) {
                if (!f.getSeverity().equalsIgnoreCase(severity)) match = false;
            }
            if (match && language != null && !language.equals("All")) {
                if (!f.getLanguage().equals(language)) match = false;
            }
            if (match) filteredFindings.add(f);
        }

        tableModel.setRowCount(0);
        for (Finding f : filteredFindings) {
            tableModel.addRow(new Object[]{
                    f.getFile(),
                    String.valueOf(f.getLine()),
                    f.getSeverity().toUpperCase(),
                    f.getMessage(),
                    f.getLanguage(),
                    f.getCategory(),
                    f.getConfidence() + "%"
            });
        }
        fileCountLabel.setText("Files: " + filteredFindings.size());
    }

    private void showDetails(Finding f) {
        if (f == null) {
            detailArea.setText("");
            codePreviewArea.setText("");
            return;
        }
        StringBuilder sb = new StringBuilder();
        sb.append("File: ").append(f.getFile()).append("\n");
        sb.append("Line: ").append(f.getLine()).append("\n");
        sb.append("Severity: ").append(f.getSeverity().toUpperCase()).append("\n");
        sb.append("Category: ").append(f.getCategory()).append("\n");
        sb.append("Type: ").append(f.getType().toUpperCase()).append("\n");
        sb.append("Confidence: ").append(f.getConfidence()).append("%\n");
        sb.append("Language: ").append(f.getLanguage()).append("\n\n");
        sb.append("Message: ").append(f.getMessage()).append("\n\n");
        sb.append("Recommendation: ").append(f.getRecommendation());
        detailArea.setText(sb.toString());

        try {
            List<String> lines = Files.readAllLines(Paths.get(f.getFile()), StandardCharsets.UTF_8);
            int line = f.getLine();
            int start = Math.max(0, line - 4);
            int end = Math.min(lines.size(), line + 3);
            StringBuilder preview = new StringBuilder();
            for (int i = start; i < end; i++) {
                preview.append(i + 1).append(": ").append(lines.get(i)).append("\n");
            }
            codePreviewArea.setText(preview.toString());
        } catch (IOException e) {
            codePreviewArea.setText("Preview unavailable");
        }
    }

    private boolean isExcludedPath(Path path) {
        Path current = path;
        while (current != null) {
            String name = current.getFileName() == null ? null : current.getFileName().toString();
            if (name != null && EXCLUDED_DIRS.contains(name)) {
                return true;
            }
            current = current.getParent();
        }
        return false;
    }

    public List<Finding> scanDirectory(File folder) throws IOException {
        if (folder == null || !folder.exists() || !folder.isDirectory()) {
            throw new IOException("Invalid directory selected.");
        }

        List<Finding> findings = new ArrayList<>();
        List<Path> files;
        try (Stream<Path> stream = Files.walk(folder.toPath())) {
            files = stream.filter(Files::isRegularFile)
                    .filter(path -> !isExcludedPath(path))
                    .sorted()
                    .toList();
        }

        for (Path file : files) {
            if (stopScan) {
                break;
            }
            findings.addAll(analyzeFile(file.toString()));
        }
        return findings;
    }

    private void browseFolder() {
        // Apply dark theme to file chooser
        UIManager.put("FileChooser.background", THEME_BG);
        UIManager.put("FileChooser.foreground", THEME_TEXT);
        UIManager.put("FileChooser.listViewBackground", THEME_SURFACE_ALT);
        UIManager.put("FileChooser.listViewForeground", THEME_TEXT);
        UIManager.put("FileChooser.listViewBorder", THEME_BORDER);
        UIManager.put("File.background", THEME_SURFACE_ALT);
        UIManager.put("File.foreground", THEME_TEXT);
        UIManager.put("Label.background", THEME_SURFACE);
        UIManager.put("Label.foreground", THEME_TEXT);
        UIManager.put("TextField.background", THEME_SURFACE_ALT);
        UIManager.put("TextField.foreground", THEME_TEXT);
        UIManager.put("ComboBox.background", THEME_SURFACE_ALT);
        UIManager.put("ComboBox.foreground", THEME_TEXT);
        UIManager.put("Button.background", THEME_SURFACE);
        UIManager.put("Button.foreground", THEME_TEXT);
        JFileChooser chooser = new JFileChooser();
        chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
        chooser.setDialogTitle("Select Target Directory");
        chooser.setBackground(THEME_BG);
        int result = chooser.showOpenDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            targetFolder = chooser.getSelectedFile();
            folderLabel.setText(targetFolder.getAbsolutePath());
            statusLabel.setText("Selected: " + targetFolder.getAbsolutePath());
            scanBtn.setEnabled(true);
        }
    }

    private void startScan() {
        if (targetFolder == null) {
            new HolographicDialog(this, "⚠ TARGET ERROR", "Please select a valid target directory.\nThe scanner requires a directory to analyze.", "WARNING").setVisible(true);
            return;
        }
        if (scanning) return;

        allFindings.clear();
        filteredFindings.clear();
        tableModel.setRowCount(0);
        updateDashboard();
        detailArea.setText("");
        codePreviewArea.setText("");
        progressBar.setValue(0);
        progressText.setText("0%");
        exportBtn.setEnabled(false);
        scanBtn.setEnabled(false);
        stopBtn.setEnabled(true);
        fileCountLabel.setText("Files: 0");
        scanning = true;
        stopScan = false;

        statusLabel.setText("Scanning in progress...");

        new Thread(() -> {
            try {
                List<Path> allFiles = new ArrayList<>();
                try (Stream<Path> stream = Files.walk(targetFolder.toPath())) {
                    allFiles = stream.filter(Files::isRegularFile)
                            .filter(path -> !isExcludedPath(path))
                            .sorted()
                            .toList();
                }

                int total = allFiles.size();
                AtomicInteger processed = new AtomicInteger(0);

                for (Path file : allFiles) {
                    if (stopScan) break;
                    SwingUtilities.invokeLater(() -> {
                        double progress = (double) processed.get() / total;
                        progressBar.setValue((int)(progress * 100));
                        progressText.setText(String.format("%d%%", (int)(progress * 100)));
                        fileCountLabel.setText("Files: " + processed.get() + "/" + total);
                        statusLabel.setText("Scanning: " + file.getFileName());
                    });

                    try {
                        List<Finding> issues = analyzeFile(file.toString());
                        for (Finding f : issues) {
                            SwingUtilities.invokeLater(() -> {
                                allFindings.add(f);
                                applyFilters();
                                updateDashboard();
                                exportBtn.setEnabled(true);
                            });
                        }
                    } catch (Exception e) {
                        e.printStackTrace();
                    }
                    processed.incrementAndGet();
                }

                SwingUtilities.invokeLater(() -> {
                    scanBtn.setEnabled(true);
                    stopBtn.setEnabled(false);
                    scanning = false;
                    progressBar.setValue(100);
                    progressText.setText("100%");

                    if (allFindings.isEmpty()) {
                        statusLabel.setText("Scan complete: ✅ NO ISSUES DETECTED - CODE IS CLEAN");
                        // Show holographic success message
                        new HolographicDialog(this,
                            "✦ SYSTEM SECURE ✦",
                            "SCAN COMPLETE: ZERO VULNERABILITIES FOUND\nYour codebase is clean and secure.\nNo issues detected across all scanned files.",
                            "SUCCESS").setVisible(true);
                    } else {
                        // Check severity levels for appropriate dialog
                        boolean hasCritical = allFindings.stream().anyMatch(f -> f.getSeverity().equalsIgnoreCase("critical"));
                        boolean hasHigh = allFindings.stream().anyMatch(f -> f.getSeverity().equalsIgnoreCase("high"));
                        String dialogType;
                        String dialogTitle;
                        String dialogMsg;

                        if (hasCritical) {
                            dialogType = "ERROR";
                            dialogTitle = "✖ CRITICAL THREATS DETECTED";
                            dialogMsg = "SCAN COMPLETE: " + allFindings.size() + " ISSUES FOUND\nCRITICAL vulnerabilities detected!\nImmediate action required to secure your codebase.";
                        } else if (hasHigh) {
                            dialogType = "WARNING";
                            dialogTitle = "⚠ HIGH RISK DETECTED";
                            dialogMsg = "SCAN COMPLETE: " + allFindings.size() + " ISSUES FOUND\nHigh severity issues require attention.\nReview and patch the identified vulnerabilities.";
                        } else {
                            dialogType = "INFO";
                            dialogTitle = "ℹ ISSUES FOUND";
                            dialogMsg = "SCAN COMPLETE: " + allFindings.size() + " ISSUES FOUND\nMedium and low severity items detected.\nReview recommendations for best practices.";
                        }

                        statusLabel.setText("Scan finished. Total findings: " + allFindings.size());
                        new HolographicDialog(this, dialogTitle, dialogMsg, dialogType).setVisible(true);
                    }
                    fileCountLabel.setText("Files: " + allFindings.size());
                    applyFilters();
                });

            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    new HolographicDialog(this, "✖ SCAN ERROR", "Scan error: " + e.getMessage() + "\nPlease check the directory and try again.", "ERROR").setVisible(true);
                    scanBtn.setEnabled(true);
                    stopBtn.setEnabled(false);
                    scanning = false;
                });
            }
        }).start();
    }

    private void stopScan() {
        stopScan = true;
        statusLabel.setText("Aborting scan...");
    }

    private void exportHtml() {
        if (allFindings.isEmpty()) {
            new HolographicDialog(this, "ℹ NO DATA", "No findings to export.\nRun a scan first to generate results.", "INFO").setVisible(true);
            return;
        }
        String timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save HTML Report");
        chooser.setSelectedFile(new File("cyberscan_report_" + timestamp + ".html"));
        int result = chooser.showSaveDialog(this);
        if (result == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            try {
                generateHtmlReport(file);
                new HolographicDialog(this, "✦ EXPORT SUCCESS", "Report saved to:\n" + file.getAbsolutePath() + "\nHTML report generated successfully.", "SUCCESS").setVisible(true);
            } catch (Exception e) {
                new HolographicDialog(this, "✖ EXPORT FAILED", "Error: " + e.getMessage() + "\nCould not save the report file.", "ERROR").setVisible(true);
            }
        }
    }

    private void generateHtmlReport(File output) throws IOException {
        Map<String, Map<String, Integer>> langSev = new HashMap<>();
        Map<String, Integer> sevTotal = new HashMap<>();
        sevTotal.put("critical", 0);
        sevTotal.put("high", 0);
        sevTotal.put("medium", 0);
        sevTotal.put("low", 0);

        for (Finding f : allFindings) {
            String lang = f.getLanguage();
            String sev = f.getSeverity().toLowerCase();
            langSev.computeIfAbsent(lang, k -> new HashMap<>()).merge(sev, 1, Integer::sum);
            sevTotal.merge(sev, 1, Integer::sum);
        }

        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html>\n<html>\n<head>\n")
            .append("<meta charset='utf-8'>\n")
            .append("<title>CyberScan Pro Report</title>\n")
            .append("<style>\n")
            .append("body { background: #0a0f1a; color: #e0f2fe; font-family: 'Segoe UI', Tahoma, Arial, sans-serif; margin: 40px; line-height: 1.5; }\n")
            .append(".container { max-width: 1400px; margin: 0 auto; background: rgba(13,23,32,0.9); padding: 30px; border-radius: 16px; border: 1px solid #1a3a4a; box-shadow: 0 0 60px rgba(0,255,200,0.15); }\n")
            .append("h1 { color: #7fffd4; font-family: 'Orbitron', sans-serif; font-size: 3.2rem; border-bottom: 2px solid #1a3a4a; padding-bottom: 15px; text-shadow: 0 0 30px rgba(127,255,212,0.4); letter-spacing: 2px; }\n")
            .append(".summary { display: flex; flex-wrap: wrap; gap: 20px; background: #0d1720; padding: 20px; border-radius: 12px; border: 1px solid #1a3a4a; margin: 20px 0; }\n")
            .append(".summary-item { background: #13212e; padding: 12px 30px; border-radius: 8px; border-left: 4px solid #7fffd4; flex: 1 1 auto; min-width: 100px; }\n")
            .append(".summary-item .label { color: #a0c4e8; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 1px; }\n")
            .append(".summary-item .value { font-size: 2.2rem; font-weight: bold; color: #e8f6f3; }\n")
            .append(".badge-critical { background: #ff5c7a; color: #fff; padding: 4px 10px; border-radius: 12px; }\n")
            .append(".badge-high { background: #ff8a5b; color: #fff; padding: 4px 10px; border-radius: 12px; }\n")
            .append(".badge-medium { background: #ffb347; color: #000; padding: 4px 10px; border-radius: 12px; }\n")
            .append(".badge-low { background: #5bc0de; color: #000; padding: 4px 10px; border-radius: 12px; }\n")
            .append("table { width: 100%; border-collapse: collapse; margin: 20px 0; font-size: 14px; }\n")
            .append("th, td { padding: 12px 14px; border: 1px solid #1a3a4a; text-align: left; }\n")
            .append("th { background: #13212e; color: #7fffd4; font-weight: bold; text-transform: uppercase; letter-spacing: 1px; }\n")
            .append("tr:nth-child(even) { background: #0d1720; }\n")
            .append("tr:hover { background: #1a2a3a; }\n")
            .append(".severity-cell { font-weight: bold; text-align: center; }\n")
            .append(".footer { margin-top: 40px; color: #4a6a7a; font-size: 0.9rem; text-align: center; border-top: 1px solid #1a3a4a; padding-top: 20px; }\n")
            .append(".language-badge { display: inline-block; background: #1a3a4a; padding: 2px 12px; border-radius: 12px; color: #7fffd4; }\n")
            .append("</style>\n</head>\n<body>\n")
            .append("<div class='container'>\n")
            .append("<h1>🛡️ CyberScan Pro – Security Report</h1>\n")
            .append("<p><strong>Target:</strong> ").append(targetFolder.getAbsolutePath()).append("</p>\n")
            .append("<p><strong>Scan Date:</strong> ").append(LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"))).append("</p>\n")
            .append("<p><strong>Total Findings:</strong> ").append(allFindings.size()).append("</p>\n")
            .append("<div class='summary'>\n")
            .append("<div class='summary-item'><span class='label'>Critical</span><br><span class='value' style='color:#ff5c7a;'>").append(sevTotal.getOrDefault("critical",0)).append("</span></div>\n")
            .append("<div class='summary-item'><span class='label'>High</span><br><span class='value' style='color:#ff8a5b;'>").append(sevTotal.getOrDefault("high",0)).append("</span></div>\n")
            .append("<div class='summary-item'><span class='label'>Medium</span><br><span class='value' style='color:#ffb347;'>").append(sevTotal.getOrDefault("medium",0)).append("</span></div>\n")
            .append("<div class='summary-item'><span class='label'>Low</span><br><span class='value' style='color:#5bc0de;'>").append(sevTotal.getOrDefault("low",0)).append("</span></div>\n")
            .append("</div>\n")
            .append("<h2>📊 Findings by Language</h2>\n<table><tr><th>Language</th><th>Critical</th><th>High</th><th>Medium</th><th>Low</th><th>Total</th></tr>\n");

        for (Map.Entry<String, Map<String, Integer>> entry : langSev.entrySet()) {
            String lang = entry.getKey();
            Map<String, Integer> sev = entry.getValue();
            int total = sev.values().stream().mapToInt(Integer::intValue).sum();
            html.append("<tr><td><span class='language-badge'>").append(lang).append("</span></td>")
                .append("<td>").append(sev.getOrDefault("critical",0)).append("</td>")
                .append("<td>").append(sev.getOrDefault("high",0)).append("</td>")
                .append("<td>").append(sev.getOrDefault("medium",0)).append("</td>")
                .append("<td>").append(sev.getOrDefault("low",0)).append("</td>")
                .append("<td><strong>").append(total).append("</strong></td></tr>\n");
        }

        html.append("</table>\n<h2>🔍 Detailed Findings</h2>\n<table><tr><th>File</th><th>Line</th><th>Severity</th><th>Message</th><th>Language</th><th>Category</th><th>Recommendation</th></tr>\n");
        for (Finding f : allFindings) {
            String sev = f.getSeverity().toUpperCase();
            html.append("<tr><td>").append(f.getFile()).append("</td>")
                .append("<td style='text-align:center;'>").append(f.getLine()).append("</td>")
                .append("<td class='severity-cell'><span class='badge-").append(f.getSeverity().toLowerCase()).append("'>").append(sev).append("</span></td>")
                .append("<td>").append(f.getMessage()).append("</td>")
                .append("<td>").append(f.getLanguage()).append("</td>")
                .append("<td>").append(f.getCategory()).append("</td>")
                .append("<td>").append(f.getRecommendation()).append("</td></tr>\n");
        }

        html.append("</table>\n<div class='footer'>Generated by CyberScan Pro • J.A.R.V.I.S. v3.0 • Matrix Rain Edition</div>\n</div>\n</body>\n</html>");

        try (BufferedWriter writer = new BufferedWriter(new FileWriter(output))) {
            writer.write(html.toString());
        }
    }

    private void toggleFullScreen() {
        GraphicsDevice gd = GraphicsEnvironment.getLocalGraphicsEnvironment().getDefaultScreenDevice();
        if (gd.isFullScreenSupported()) {
            if (isUndecorated()) {
                dispose();
                setUndecorated(false);
                setVisible(true);
                gd.setFullScreenWindow(null);
            } else {
                dispose();
                setUndecorated(true);
                setVisible(true);
                gd.setFullScreenWindow(this);
            }
        }
    }

    // ========================================================================
    // Matrix Rain Background Panel (Swing)
    // ========================================================================

    private static class MatrixRainPanel extends JPanel {
        private final List<Drop> drops = new ArrayList<>();
        private final String characters = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ!@#$%^&*()_+-=[]{}|;:,.<>?/~";
        private final Font font = new Font("Consolas", Font.BOLD, 10);
        private javax.swing.Timer timer;

        public MatrixRainPanel() {
            setBackground(THEME_BG);
            setOpaque(true);
            addComponentListener(new ComponentAdapter() {
                @Override
                public void componentResized(ComponentEvent e) {
                    initDrops();
                }
            });
        }

        public void startAnimation() {
            timer = new javax.swing.Timer(50, e -> updateRain());
            timer.start();
        }

        public void stopAnimation() {
            if (timer != null) timer.stop();
        }

        private void initDrops() {
            int width = getWidth();
            int height = getHeight();
            if (width <= 0 || height <= 0) return;

            drops.clear();
            FontMetrics fm = getFontMetrics(font);
            int charWidth = fm.charWidth('W');
            int charHeight = fm.getHeight();
            int cols = Math.max(1, width / charWidth);

            Random rand = new Random();
            for (int col = 0; col < cols; col++) {
                int x = col * charWidth + charWidth / 2;
                int y = -rand.nextInt(height);
                int speed = 2 + rand.nextInt(4);
                int length = 5 + rand.nextInt(10);
                drops.add(new Drop(x, y, speed, length));
            }
        }

        private void updateRain() {
            int height = getHeight();
            int charHeight = getFontMetrics(font).getHeight();
            Random rand = new Random();

            for (Drop drop : drops) {
                drop.y += drop.speed;
                if (drop.y > height + drop.length * charHeight) {
                    drop.y = -rand.nextInt(30) * charHeight;
                    drop.speed = 2 + rand.nextInt(4);
                    drop.length = 5 + rand.nextInt(10);
                }
            }
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            super.paintComponent(g);
            Graphics2D g2d = (Graphics2D) g;
            g2d.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);

            int width = getWidth();
            int height = getHeight();
            if (width <= 0 || height <= 0) return;

            FontMetrics fm = g2d.getFontMetrics(font);
            int charHeight = fm.getHeight();

            for (Drop drop : drops) {
                for (int i = 0; i < drop.length; i++) {
                    int y = (int) (drop.y - i * charHeight);
                    if (y < 0 || y > height) continue;
                    char ch = characters.charAt((int)(Math.random() * characters.length()));
                    int alpha = (int) (255 * Math.max(0, Math.min(1, 1 - (Math.abs(y) / (double)height))));
                    g2d.setColor(new Color(72, 209, 204, alpha));
                    g2d.setFont(font);
                    g2d.drawString(String.valueOf(ch), drop.x, y);
                }
            }
        }

        private static class Drop {
            int x, y;
            int speed;
            int length;
            Drop(int x, int y, int speed, int length) {
                this.x = x; this.y = y; this.speed = speed; this.length = length;
            }
        }
    }

    // ========================================================================
    // Main
    // ========================================================================

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> new CyberScanPro());
    }
}