// BAD: InsecureHello.java
// Day 1 — Example of what NOT to do

public class InsecureHello {

    // ❌ Hardcoded credentials in source code
    private static final String DB_PASSWORD = "admin123";
    private static final String API_KEY = "sk-abc123xyz789";

    public static void main(String[] args) {
        // ❌ Printing to stdout with no thought — in production,
        // stdout often goes to logs that attackers can access
        System.out.println("Hello, World!");

        // ❌ Printing sensitive data — this ends up in logs!
        System.out.println("Connecting with password: " + DB_PASSWORD);
        System.out.println("API Key: " + API_KEY);

        // ❌ No error handling — stack traces expose internal paths,
        // class names, library versions to attackers
        String result = null;
        System.out.println(result.length()); // NullPointerException!
    }
}
