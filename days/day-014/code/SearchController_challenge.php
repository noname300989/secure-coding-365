<?php
/**
 * Mini Challenge — Day 14: Functions & Input Sanitization
 *
 * Write a validate_search_params() function for a product search API.
 *
 * Parameters to validate:
 * ┌─────────────┬────────┬─────────────────────────────────────────────────┐
 * │ Parameter   │ Type   │ Constraints                                     │
 * ├─────────────┼────────┼─────────────────────────────────────────────────┤
 * │ q           │ string │ 2–100 chars, alphanumeric + spaces + hyphens    │
 * │ category_id │ int    │ 1–500, OPTIONAL (default: null)                 │
 * │ sort        │ string │ one of: price_asc, price_desc, newest, rating   │
 * │ page        │ int    │ 1–999, OPTIONAL (default: 1)                    │
 * └─────────────┴────────┴─────────────────────────────────────────────────┘
 *
 * Returns: array with typed values on success, false if ANY required param fails
 *
 * Example success: [
 *     'q'           => 'blue running shoes',
 *     'category_id' => 42,
 *     'sort'        => 'price_asc',
 *     'page'        => 1,
 * ]
 */

// ── Your implementation here ──────────────────────────────────────────────────

function validate_search_params(array $input): array|false
{
    // TODO: Validate 'q' — required, 2–100 chars, whitelist regex
    // Hint: preg_match('/^[a-zA-Z0-9 \-]{2,100}$/', $q)

    // TODO: Validate 'category_id' — optional int 1–500
    // Hint: use filter_var + FILTER_VALIDATE_INT with options array

    // TODO: Validate 'sort' — required, must be in allowed list
    // Hint: in_array($sort, ['price_asc', 'price_desc', 'newest', 'rating'], true)

    // TODO: Validate 'page' — optional int 1–999, default 1
    // Hint: similar to category_id

    // TODO: Return typed array or false
    return false; // Replace this
}

// ── Test harness — run with: php SearchController_challenge.php ───────────────

function run_tests(): void
{
    $tests = [
        // [input, should_pass, description]
        [['q' => 'blue shoes', 'sort' => 'price_asc'], true, 'Valid minimal input'],
        [['q' => 'blue shoes', 'sort' => 'price_asc', 'category_id' => '42', 'page' => '3'], true, 'Valid full input'],
        [['q' => 'a', 'sort' => 'price_asc'], false, 'q too short (1 char)'],
        [['q' => 'blue shoes', 'sort' => 'invalid_sort'], false, 'Invalid sort value'],
        [['q' => 'blue shoes', 'sort' => 'price_asc', 'category_id' => '0'], false, 'category_id below min'],
        [['q' => 'blue shoes', 'sort' => 'price_asc', 'category_id' => '501'], false, 'category_id above max'],
        [['q' => 'blue shoes', 'sort' => 'price_asc', 'page' => '0'], false, 'page below min'],
        [['q' => '<script>alert(1)</script>', 'sort' => 'price_asc'], false, 'XSS payload in q'],
        [['sort' => 'price_asc'], false, 'Missing required q'],
        [['q' => 'blue shoes'], false, 'Missing required sort'],
        [['q' => 'blue shoes', 'sort' => 'price_asc', 'page' => '1000'], false, 'page above max'],
    ];

    $passed = 0;
    $failed = 0;

    foreach ($tests as [$input, $should_pass, $description]) {
        $result = validate_search_params($input);
        $did_pass = ($result !== false);

        if ($did_pass === $should_pass) {
            echo "  ✅ PASS: $description\n";
            if ($did_pass) {
                echo "        Result: " . json_encode($result) . "\n";
            }
            $passed++;
        } else {
            $expected = $should_pass ? 'pass' : 'fail';
            $got      = $did_pass ? 'passed' : 'failed';
            echo "  ❌ FAIL: $description (expected: $expected, got: $got)\n";
            $failed++;
        }
    }

    echo "\n--- Results: $passed/" . count($tests) . " tests passed ---\n";
}

echo "Running Day 14 Challenge Tests...\n\n";
run_tests();

// ── Reference solution (uncomment to check your work) ─────────────────────────
/*
function validate_search_params(array $input): array|false
{
    // q — required, 2–100 chars, alphanumeric + spaces + hyphens
    $q = $input['q'] ?? null;
    if (!is_string($q) || !preg_match('/^[a-zA-Z0-9 \-]{2,100}$/', $q)) {
        return false;
    }

    // sort — required, strict enum allowlist
    $sort = $input['sort'] ?? null;
    $allowed_sorts = ['price_asc', 'price_desc', 'newest', 'rating'];
    if (!in_array($sort, $allowed_sorts, true)) {
        return false;
    }

    // category_id — optional, int 1–500
    $category_id = null;
    if (isset($input['category_id'])) {
        $filtered = filter_var($input['category_id'], FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1, 'max_range' => 500]
        ]);
        if ($filtered === false) return false;
        $category_id = (int) $filtered;
    }

    // page — optional, int 1–999, default 1
    $page = 1;
    if (isset($input['page'])) {
        $filtered = filter_var($input['page'], FILTER_VALIDATE_INT, [
            'options' => ['min_range' => 1, 'max_range' => 999]
        ]);
        if ($filtered === false) return false;
        $page = (int) $filtered;
    }

    return [
        'q'           => $q,
        'category_id' => $category_id,
        'sort'        => $sort,
        'page'        => $page,
    ];
}
*/
