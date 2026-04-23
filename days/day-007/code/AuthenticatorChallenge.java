// AuthenticatorChallenge.java
// Mini challenge: Fix this insecure class hierarchy using Template Method + final + sealed
// Day 7 challenge — OOP Part 2: Inheritance & Polymorphism

// ================================================================
// INSECURE VERSION (what you need to fix)
// ================================================================

class InsecureAuthenticator {
    // PROBLEM 1: authenticate() is public and overrideable
    public boolean authenticate(String username, String password) {
        return database.checkCredentials(username, password);
    }

    // PROBLEM 2: login() calls authenticate() polymorphically
    // Any subclass can completely bypass authentication
    public void login(String username, String password) {
        if (authenticate(username, password)) {
            session.createSession(username);
        }
    }
}

// PROBLEM 3: DevAuthenticator bypasses all auth — deployed to prod by mistake
class DevAuthenticator extends InsecureAuthenticator {
    @Override
    public boolean authenticate(String username, String password) {
        return true; // CRITICAL: backdoor if deployed to production!
    }
}

// ================================================================
// YOUR TASK: Implement the secure version below
// ================================================================

// Hints:
// 1. Make login() final — it should call a private coreAuthenticate() first
// 2. Add a protected hook checkRateLimit(username) that subclasses can customize
// 3. Make the class sealed, permitting only ProductionAuthenticator and TestAuthenticator
// 4. For build-scope isolation of TestAuthenticator:
//    - Maven: add to src/test/java (not src/main/java)
//    - Gradle: add to test sourceSet
//    - This ensures DevAuthenticator can never be in the production classpath

// TODO: Implement SecureAuthenticator here
public abstract sealed class SecureAuthenticator
    permits ProductionAuthenticator, TestAuthenticator {
    // YOUR IMPLEMENTATION HERE
}

// TODO: Implement ProductionAuthenticator
public final class ProductionAuthenticator extends SecureAuthenticator {
    // YOUR IMPLEMENTATION HERE
}

// TODO: Implement TestAuthenticator (only in src/test/java!)
public final class TestAuthenticator extends SecureAuthenticator {
    // YOUR IMPLEMENTATION HERE — allow configuring test credentials
}

// ================================================================
// Expected behavior after your fix:
// - login() is final — no subclass can reroute auth flow
// - coreAuthenticate() is private — invisible to subclasses
// - TestAuthenticator exists only in test classpath (Maven/Gradle scope)
// - sealed ensures no mystery subclasses in production
// ================================================================
