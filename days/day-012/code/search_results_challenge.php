<?php
// search_results_challenge.php
// MINI CHALLENGE: Fix all 7 XSS vulnerabilities in this search results page
// Each issue is labeled. Your task: identify the context and apply the right fix.

// =====================================================
// HELPER FUNCTIONS (your toolkit — already secure)
// =====================================================

function e(string $value): string {
    return htmlspecialchars($value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

function js(mixed $value): string {
    return json_encode(
        $value,
        JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP | JSON_UNESCAPED_UNICODE
    );
}

// =====================================================
// INPUT: Read and VALIDATE query parameters
// =====================================================

// Issue 3 & 4: Allowlist sort and category params
$allowedSort = ['relevance', 'date', 'price'];
$allowedCats = ['all', 'books', 'electronics', 'clothing'];

$query    = $_GET['q'] ?? '';
$category = in_array($_GET['cat'] ?? 'all', $allowedCats, true)
            ? $_GET['cat']
            : 'all';
$sort     = in_array($_GET['sort'] ?? 'relevance', $allowedSort, true)
            ? $_GET['sort']
            : 'relevance';

// Simulate DB results (in real app: parameterized query, encode on output)
$results = [
    ['title' => $_GET['inject_test'] ?? 'Normal Result', 'url' => 'https://example.com/product/1'],
    ['title' => 'Second Result', 'url' => 'https://example.com/product/2'],
];

// =====================================================
// SECURE OUTPUT — fix applied for each issue
// =====================================================
?>
<html>
<head>
  <!-- Issue 1 FIX: HTML title context → htmlspecialchars -->
  <title>Search: <?= e($query) ?></title>
</head>
<body>

  <!-- Issue 2 FIX: HTML body context → htmlspecialchars -->
  <h2>Results for: <?= e($query) ?></h2>

  <form action="/search" method="get">
    <!-- Issue 3 FIX: HTML attribute, double-quote → ENT_QUOTES handles both -->
    <input type="text" name="q" value="<?= e($query) ?>">

    <!-- Issue 4 FIX: single-quote attribute → ENT_QUOTES encodes ' too -->
    <input type="hidden" name="cat" value='<?= e($category) ?>'>
  </form>

  <script>
    // Issue 5 FIX: JS string context → json_encode with JSON_HEX_* flags
    // NOT htmlspecialchars — that's HTML encoding, not JS encoding!
    gtag('event', 'search', { search_term: <?= js($query) ?> });
  </script>

  <?php foreach ($results as $r): ?>
    <div class="result">
      <!-- Issue 6 FIX: DB-sourced title → still encode on output! -->
      <h3><?= e($r['title']) ?></h3>

      <?php
        // Issue 7 FIX: URL in href → validate scheme to block javascript:
        $safeUrl = '/';
        $scheme = parse_url($r['url'], PHP_URL_SCHEME);
        if (in_array($scheme, ['http', 'https'], true)) {
            $safeUrl = $r['url']; // safe external URL
        }
      ?>
      <!-- Encode the already-validated URL in the attribute context -->
      <a href="<?= e($safeUrl) ?>">Visit</a>
    </div>
  <?php endforeach; ?>

</body>
</html>

<?php
/*
 * BONUS: Content-Security-Policy header for defense in depth
 * This tells the browser which scripts are allowed to run.
 * Even if an XSS payload gets through, CSP can block its execution.
 *
 * header("Content-Security-Policy: default-src 'self'; script-src 'self' https://www.googletagmanager.com");
 * header("X-Content-Type-Options: nosniff");
 * header("X-Frame-Options: DENY");
 * header("Referrer-Policy: strict-origin-when-cross-origin");
 *
 * Note: CSP is defense-in-depth, NOT a replacement for output encoding!
 */
