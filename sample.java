public class SampleVuln {
    public static void main(String[] args) throws Exception {
        Runtime.getRuntime().exec("echo hello");
    }
}
