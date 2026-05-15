<?php
/**
 * Admin Payout Operations — /public_html/admin/seller_payouts.php
 *
 * Manages internal payout workflow only.
 * Does NOT send money externally. Mark Paid only records that the admin
 * has paid the seller manually outside the system.
 *
 * Actions are delegated exclusively to seller_balance.php helpers.
 */

// ── 1. Session must start before anything else ───────────────────────────────
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

// ── 2. Load guard files ───────────────────────────────────────────────────────
foreach ([
    __DIR__ . '/_guard.php',
    __DIR__ . '/admin_auth.php',
    dirname(__DIR__) . '/includes/admin_auth.php',
    dirname(__DIR__) . '/includes/auth_admin.php',
] as $_guardFile) {
    if (is_file($_guardFile)) {
        require_once $_guardFile;
        break;
    }
}

// ── 3. Role detection ─────────────────────────────────────────────────────────
if (!function_exists('bv_sp_get_role')) {
    function bv_sp_get_role(): string
    {
        $candidates = [
            $_SESSION['admin']['role']     ?? null,
            $_SESSION['user']['role']      ?? null,
            $_SESSION['auth_user']['role'] ?? null,
            $_SESSION['role']              ?? null,
            $_SESSION['admin_role']        ?? null,
        ];
        foreach ($candidates as $r) {
            if ($r !== null && $r !== '') { return strtolower(trim((string)$r)); }
        }
        foreach (['admin_role', 'role', 'user_role'] as $k) {
            if (!empty($_SESSION[$k])) { return strtolower(trim((string)$_SESSION[$k])); }
        }
        if (is_array($_SESSION['admin'] ?? null)) {
            foreach (['role', 'admin_role', 'type'] as $k) {
                if (!empty($_SESSION['admin'][$k])) { return strtolower(trim((string)$_SESSION['admin'][$k])); }
            }
        }
        return '';
    }
}

if (!function_exists('bv_sp_admin_id')) {
    function bv_sp_admin_id(): int
    {
        foreach (['admin_id', 'user_id', 'id'] as $k) {
            if (!empty($_SESSION[$k])) { return (int)$_SESSION[$k]; }
        }
        if (is_array($_SESSION['admin'] ?? null)) {
            foreach (['id', 'admin_id', 'user_id'] as $k) {
                if (!empty($_SESSION['admin'][$k])) { return (int)$_SESSION['admin'][$k]; }
            }
        }
        return 0;
    }
}

if (!function_exists('bv_sp_is_authorized')) {
    function bv_sp_is_authorized(): bool
    {
        $role = bv_sp_get_role();
        if (in_array($role, ['admin', 'superadmin', 'super_admin', 'owner'], true)) { return true; }
        return !empty($_SESSION['admin_logged_in'])
            || !empty($_SESSION['is_admin'])
            || !empty($_SESSION['admin']);
    }
}

if (!function_exists('bv_sp_is_super')) {
    function bv_sp_is_super(): bool
    {
        return in_array(bv_sp_get_role(), ['superadmin', 'super_admin', 'owner'], true);
    }
}

// ── 4. Auth gate ──────────────────────────────────────────────────────────────
if (!bv_sp_is_authorized()) {
    http_response_code(403);
    echo '<!doctype html><html><body><h1>403 Forbidden</h1></body></html>';
    exit;
}

// ── 5. Load seller_balance.php helper ─────────────────────────────────────────
$_sbHelper   = dirname(__DIR__) . '/includes/seller_balance.php';
$sbAvailable = is_file($_sbHelper);
if ($sbAvailable) {
    require_once $_sbHelper;
}

// ── 6. Local helpers ──────────────────────────────────────────────────────────
if (!function_exists('h')) {
    function h($v): string { return htmlspecialchars((string)$v, ENT_QUOTES, 'UTF-8'); }
}

if (!function_exists('money_fmt')) {
    function money_fmt($amount, string $currency = 'USD'): string
    {
        $currency = strtoupper(trim($currency) ?: 'USD');
        return $currency . ' ' . number_format((float)$amount, 2, '.', ',');
    }
}

// ── DB layer ───────────────────────────────────────────────────────────────────
// KEY FIX: Try bv_seller_balance_pdo() FIRST — the helper's connection always
// works (it powers all the balance mutations). This solves the silent "table
// not found" failure caused by bv_sp_pdo() looking in wrong global variables.
if (!function_exists('bv_sp_pdo')) {
    function bv_sp_pdo(): ?PDO
    {
        // 1. Reuse the helper's own PDO connection if already available.
        if (function_exists('bv_seller_balance_pdo')) {
            try {
                $h = bv_seller_balance_pdo();
                if ($h instanceof PDO) { return $h; }
            } catch (Throwable) {}
        }
        // 2. Common global names (both cases).
        foreach (['pdo', 'PDO', 'db', 'conn', 'database', 'DB'] as $k) {
            if (isset($GLOBALS[$k]) && $GLOBALS[$k] instanceof PDO) { return $GLOBALS[$k]; }
        }
        // 3. Try to load a db config file.
        foreach ([
            dirname(__DIR__) . '/config/db.php',
            dirname(__DIR__) . '/includes/db.php',
            dirname(__DIR__) . '/config/database.php',
        ] as $f) {
            if (is_file($f)) {
                require_once $f;
                foreach (['pdo', 'PDO', 'db', 'conn', 'database', 'DB'] as $k) {
                    if (isset($GLOBALS[$k]) && $GLOBALS[$k] instanceof PDO) { return $GLOBALS[$k]; }
                }
            }
        }
        return null;
    }
}

if (!function_exists('bv_sp_q')) {
    function bv_sp_q(string $sql, array $p = []): array
    {
        $pdo = bv_sp_pdo();
        if (!$pdo) { return []; }
        try {
            $s = $pdo->prepare($sql);
            $s->execute($p);
            return $s->fetchAll(PDO::FETCH_ASSOC) ?: [];
        } catch (Throwable) { return []; }
    }
}

if (!function_exists('bv_sp_q1')) {
    function bv_sp_q1(string $sql, array $p = []): ?array
    {
        $rows = bv_sp_q($sql, $p);
        return $rows[0] ?? null;
    }
}

// Cache table/column checks to avoid repeated SHOW queries.
$_bvSpTableCache  = [];
$_bvSpColumnCache = [];

if (!function_exists('table_exists')) {
    function table_exists(string $t): bool
    {
        global $_bvSpTableCache;
        if ($t === '') { return false; }
        if (isset($_bvSpTableCache[$t])) { return $_bvSpTableCache[$t]; }
        $_bvSpTableCache[$t] = (bool)bv_sp_q1('SHOW TABLES LIKE ?', [$t]);
        return $_bvSpTableCache[$t];
    }
}

if (!function_exists('column_exists')) {
    function column_exists(string $t, string $c): bool
    {
        global $_bvSpColumnCache;
        if ($t === '' || $c === '') { return false; }
        $key = $t . '.' . $c;
        if (isset($_bvSpColumnCache[$key])) { return $_bvSpColumnCache[$key]; }
        $_bvSpColumnCache[$key] = (bool)bv_sp_q1(
            'SHOW COLUMNS FROM `' . str_replace('`', '``', $t) . '` LIKE ?', [$c]
        );
        return $_bvSpColumnCache[$key];
    }
}

// ── Seller label ──────────────────────────────────────────────────────────────
if (!function_exists('seller_label')) {
    function seller_label($row): string
    {
        // Prefer farm_name from seller_applications.
        if (!empty($row['farm_name'])) { return (string)$row['farm_name']; }
       if (!empty($row['display_name'])) { return (string)$row['display_name']; }		
        // Full name from users.
        $fn = trim(trim((string)($row['first_name'] ?? '')) . ' ' . trim((string)($row['last_name'] ?? '')));
        if ($fn !== '') { return $fn; }
        if (!empty($row['email'])) { return (string)$row['email']; }
        return 'Seller #' . ($row['seller_id'] ?? $row['id'] ?? '?');
    }
}

if (!function_exists('status_badge_class')) {
    function status_badge_class(string $s): string
    {
        $s = strtolower($s);
        if (in_array($s, ['approved', 'paid', 'completed', 'success'], true)) { return 'badge-success'; }
        if (in_array($s, ['rejected', 'failed', 'cancelled', 'canceled'], true)) { return 'badge-danger'; }
        if (in_array($s, ['pending', 'requested'], true)) { return 'badge-warning'; }
        return 'badge-secondary';
    }
}

// ── CSRF ──────────────────────────────────────────────────────────────────────
if (empty($_SESSION['_csrf_admin_seller_payouts']['actions'])) {
    $_SESSION['_csrf_admin_seller_payouts']['actions'] = bin2hex(random_bytes(32));
}
$_csrfToken = $_SESSION['_csrf_admin_seller_payouts']['actions'];

if (!function_exists('csrf_token')) {
    function csrf_token(): string { return $GLOBALS['_csrfToken']; }
}
if (!function_exists('csrf_verify')) {
    function csrf_verify(): void
    {
        $t = (string)($_POST['csrf_token'] ?? '');
        if (!hash_equals($_SESSION['_csrf_admin_seller_payouts']['actions'] ?? '', $t)) {
            throw new RuntimeException('Invalid CSRF token.');
        }
    }
}

// ── Flash ─────────────────────────────────────────────────────────────────────
if (!function_exists('flash_set')) {
    function flash_set(string $type, string $msg): void
    {
        $_SESSION['_flash_sp'][$type === 'error' ? 'errors' : 'messages'][] = $msg;
    }
}
if (!function_exists('flash_get')) {
    function flash_get(): array
    {
        $f   = $_SESSION['_flash_sp'] ?? [];
        unset($_SESSION['_flash_sp']);
        $leg = $_SESSION['seller_payouts_flash'] ?? [];
        unset($_SESSION['seller_payouts_flash']);
        return [
            'messages' => array_merge($f['messages'] ?? [], $leg['messages'] ?? []),
            'errors'   => array_merge($f['errors']   ?? [], $leg['errors']   ?? []),
        ];
    }
}
if (!function_exists('redirect_safe')) {
    function redirect_safe(): never
    {
        header('Location: seller_payouts.php', true, 303);
        exit;
    }
}

// ── Balance reader ────────────────────────────────────────────────────────────
// Maps all key variants from bv_seller_balance_get() and the seller_balances
// snapshot columns (available_balance, pending_balance, held_balance, etc.).
if (!function_exists('bv_sp_read_balance')) {
    function bv_sp_read_balance(int $sid): array
    {
        $zero = ['available' => 0.0, 'pending' => 0.0, 'locked' => 0.0,
                 'paid_out'  => 0.0, 'total'   => 0.0, 'currency' => 'USD'];
        if ($sid <= 0) { return $zero; }

        // Prefer source-of-truth helper.
        if (function_exists('bv_seller_balance_get')) {
            try {
                $b = bv_seller_balance_get($sid);
                if (is_array($b) && $b) {
                   $hasAny = static function(array $b, array $keys): bool {
                        foreach ($keys as $k) {
                            if (array_key_exists($k, $b) && is_numeric($b[$k])) { return true; }
                        }
                        return false;
                    };					
                    $pick = static function(array $b, array $keys): float {
                        foreach ($keys as $k) {
                            if (array_key_exists($k, $b) && is_numeric($b[$k])) { return (float)$b[$k]; }
                        }
                        return 0.0;
                    };
                    $knownKeys = [
                        'available', 'available_balance', 'available_amount',
                        'pending', 'pending_balance', 'pending_release',
                        'held', 'held_balance', 'locked', 'locked_balance', 'refund_locked',
                        'paid_out', 'paid_out_balance', 'paidout', 'total_paid_out',
                        'total', 'total_balance', 'total_earned_gross', 'balance',
                    ];
                   if ($hasAny($b, $knownKeys)) {
                        return [
                            'available' => $pick($b, ['available', 'available_balance', 'available_amount']),
                            'pending'   => max(0.0, $pick($b, ['pending', 'pending_balance', 'pending_release'])),
                            'locked'    => $pick($b, ['locked', 'locked_balance', 'refund_locked', 'held_balance']),
                            'paid_out'  => $pick($b, ['paid_out', 'paid_out_balance']),
                            'total'     => $pick($b, ['total', 'total_balance', 'balance']),
                            'currency'  => (string)($b['currency'] ?? 'USD'),
                            '_source'   => 'helper',
                        ];
                    }  
                }
            } catch (Throwable) {}
        }

         // Fallback: direct seller_balance_entries ledger read (read-only display).
        if (table_exists('seller_balance_entries')) {
            $row = bv_sp_q1(
                "SELECT
                    COALESCE(SUM(CASE WHEN status = 'pending' THEN amount ELSE 0 END),0) AS pending_amount,
                    COALESCE(SUM(CASE WHEN available_at IS NOT NULL AND paid_out_at IS NULL THEN amount ELSE 0 END),0) AS available_amount,
                    COALESCE(SUM(CASE WHEN paid_out_at IS NOT NULL THEN amount ELSE 0 END),0) AS paid_out_amount,
                    COALESCE(SUM(CASE WHEN LOWER(COALESCE(status,'')) IN ('locked','held','hold','on_hold','refund_locked') THEN amount ELSE 0 END),0) AS locked_amount,
                    COALESCE(SUM(amount),0) AS total_amount,
                    COALESCE(MAX(NULLIF(currency,'')),'USD') AS currency
                 FROM seller_balance_entries
                 WHERE seller_id = ?",
                [$sid]
            );
            if ($row) {
                return [
                 'available' => (float)($row['available_amount'] ?? 0),
                    'pending'   => max(0.0, (float)($row['pending_amount'] ?? 0)),
                    'locked'    => (float)($row['locked_amount'] ?? 0),
                    'paid_out'  => (float)($row['paid_out_amount'] ?? 0),
                    'total'     => (float)($row['total_amount'] ?? 0),
                    'currency'  => (string)($row['currency'] ?? 'USD'),
                    '_source'   => 'seller_balance_entries',
                ];
            }
        }
        return $zero;
    }
}

// ── Capability flags ──────────────────────────────────────────────────────────
$isSuperAdmin      = bv_sp_is_super();
$pdo               = bv_sp_pdo();
$dbAvailable       = $pdo !== null;
$hasPayoutsTable   = $dbAvailable && table_exists('seller_payout_requests');
$hasLedgerTable    = $dbAvailable && table_exists('seller_balance_entries');
$hasSellerLedger   = $dbAvailable && table_exists('seller_ledger');
$hasSellerBalTable = $dbAvailable && table_exists('seller_balances');
$hasUsersTable     = $dbAvailable && table_exists('users');
$hasSellerApps     = $dbAvailable && table_exists('seller_applications');

$hasApprove        = $sbAvailable && $hasPayoutsTable && function_exists('bv_seller_balance_approve_payout');
$hasReject         = $sbAvailable && $hasPayoutsTable && function_exists('bv_seller_balance_reject_payout');
$hasMarkPaid       = $sbAvailable && $hasPayoutsTable && $isSuperAdmin && function_exists('bv_seller_balance_mark_payout_paid');
$hasReleasePending = $sbAvailable && $isSuperAdmin && function_exists('bv_seller_balance_release_pending') && function_exists('bv_seller_balance_get');
$hasAdjustBalance  = $sbAvailable && $isSuperAdmin && function_exists('bv_seller_balance_admin_adjust');

// ── POST actions ──────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        csrf_verify();
        if (!$sbAvailable) {
            throw new RuntimeException('seller_balance.php helper is missing; all payout actions are disabled.');
        }
        $action  = (string)($_POST['action'] ?? '');
        $adminId = bv_sp_admin_id();

        if ($action === 'approve_request') {
            if (!$hasApprove) { throw new RuntimeException('bv_seller_balance_approve_payout() is unavailable.'); }
            $requestId = (int)($_POST['request_id'] ?? 0);
            if ($requestId <= 0) { throw new RuntimeException('Invalid request ID.'); }
            $req = bv_sp_q1('SELECT id, status FROM seller_payout_requests WHERE id = ? LIMIT 1', [$requestId]);
            if (!$req) { throw new RuntimeException('Payout request #' . $requestId . ' not found.'); }
            $cs = strtolower((string)($req['status'] ?? ''));
            if (!in_array($cs, ['pending', 'requested'], true)) {
                flash_set('error', 'Payout #' . $requestId . ' is already ' . $cs . '. No action taken.');
                redirect_safe();
            }
            $result = bv_seller_balance_approve_payout($requestId, $adminId);
            if ($result === false) { throw new RuntimeException('Approve returned false for request #' . $requestId . '.'); }
            flash_set('message', 'Payout request #' . $requestId . ' approved.');

        } elseif ($action === 'reject_request') {
            if (!$hasReject) { throw new RuntimeException('bv_seller_balance_reject_payout() is unavailable.'); }
            $requestId = (int)($_POST['request_id'] ?? 0);
            $adminNote = trim((string)($_POST['admin_note'] ?? ''));
            if ($requestId <= 0) { throw new RuntimeException('Invalid request ID.'); }
            if ($adminNote === '') { throw new RuntimeException('Admin note is required to reject a request.'); }
            $req = bv_sp_q1('SELECT id, status FROM seller_payout_requests WHERE id = ? LIMIT 1', [$requestId]);
            if (!$req) { throw new RuntimeException('Payout request #' . $requestId . ' not found.'); }
            $cs = strtolower((string)($req['status'] ?? ''));
            if (!in_array($cs, ['pending', 'requested', 'approved'], true)) {
                flash_set('error', 'Payout #' . $requestId . ' is already ' . $cs . '. No action taken.');
                redirect_safe();
            }
            $result = bv_seller_balance_reject_payout($requestId, $adminId, $adminNote);
            if ($result === false) { throw new RuntimeException('Reject returned false for request #' . $requestId . '.'); }
            flash_set('message', 'Payout request #' . $requestId . ' rejected.');

        } elseif ($action === 'mark_paid') {
            if (!bv_sp_is_super()) { throw new RuntimeException('Only superadmin/owner users can mark payouts as paid.'); }
            if (!$hasMarkPaid) { throw new RuntimeException('bv_seller_balance_mark_payout_paid() is unavailable.'); }
            $requestId        = (int)($_POST['request_id'] ?? 0);
            $paymentReference = trim((string)($_POST['payment_reference'] ?? ''));
            $paymentMethod    = trim((string)($_POST['payment_method'] ?? 'manual'));
            $adminNote        = trim((string)($_POST['admin_note'] ?? ''));
            if ($requestId <= 0)          { throw new RuntimeException('Invalid request ID.'); }
            if ($paymentReference === '')  { throw new RuntimeException('Payment reference is required.'); }
            $req = bv_sp_q1('SELECT id, status FROM seller_payout_requests WHERE id = ? LIMIT 1', [$requestId]);
            if (!$req) { throw new RuntimeException('Payout request #' . $requestId . ' not found.'); }
            $cs = strtolower((string)($req['status'] ?? ''));
            if ($cs === 'paid') {
                flash_set('error', 'Payout #' . $requestId . ' is already paid. No action taken.');
                redirect_safe();
            }
            if ($cs !== 'approved') {
                throw new RuntimeException('Payout #' . $requestId . ' must be approved before marking paid (current: ' . $cs . ').');
            }
            $result = bv_seller_balance_mark_payout_paid($requestId, $adminId, $paymentReference, $paymentMethod, $adminNote);
            if ($result === false) { throw new RuntimeException('mark_payout_paid() returned false for request #' . $requestId . '.'); }
            flash_set('message', 'Payout #' . $requestId . ' marked as paid (ref: ' . $paymentReference . ').');

        } elseif ($action === 'release_pending') {
            if (!bv_sp_is_super()) { throw new RuntimeException('Only superadmin/owner can release pending balances.'); }
            if (!$hasReleasePending) { throw new RuntimeException('Pending release helpers unavailable.'); }
            $sellerId = (int)($_POST['seller_id'] ?? 0);
            if ($sellerId <= 0) { throw new RuntimeException('Invalid seller ID.'); }
            $bal = bv_sp_read_balance($sellerId);
            if ((float)($bal['pending'] ?? 0) <= 0) {
                throw new RuntimeException('Seller #' . $sellerId . ' has no pending balance to release.');
            }
            bv_seller_balance_release_pending($sellerId, (float)$bal['pending'], $adminId);
            flash_set('message', 'Pending balance released for seller #' . $sellerId . '.');

        } elseif ($action === 'adjust_balance') {
            if (!bv_sp_is_super()) { throw new RuntimeException('Only superadmin/owner can adjust balances.'); }
            if (!$hasAdjustBalance) { throw new RuntimeException('bv_seller_balance_admin_adjust() unavailable.'); }
            $sellerId  = (int)($_POST['seller_id'] ?? 0);
            $amount    = abs((float)($_POST['amount'] ?? 0));
            $direction = trim((string)($_POST['direction'] ?? ''));
            $adminNote = trim((string)($_POST['admin_note'] ?? ''));
            if ($sellerId <= 0)                                   { throw new RuntimeException('Invalid seller ID.'); }
            if ($amount <= 0)                                     { throw new RuntimeException('Amount must be positive.'); }
            if (!in_array($direction, ['credit', 'debit'], true)) { throw new RuntimeException('Direction must be credit or debit.'); }
            if ($adminNote === '')                                 { throw new RuntimeException('Admin note is required.'); }
            bv_seller_balance_admin_adjust($sellerId, $amount, $direction, $adminNote, $adminId);
            flash_set('message', 'Balance adjusted for seller #' . $sellerId . '.');

        } else {
            throw new RuntimeException('Unknown action: ' . h($action));
        }
    } catch (Throwable $e) {
        flash_set('error', $e->getMessage());
    }
    redirect_safe();
}

// ── Read flash ────────────────────────────────────────────────────────────────
$flash    = flash_get();
$messages = $flash['messages'];
$errors   = $flash['errors'];

// ── Filters ───────────────────────────────────────────────────────────────────
$filterStatus   = trim((string)($_GET['status']    ?? ''));
$filterKeyword  = trim((string)($_GET['keyword']   ?? ''));
$filterDateFrom = trim((string)($_GET['date_from'] ?? ''));
$filterDateTo   = trim((string)($_GET['date_to']   ?? ''));

// ── Payout Requests ───────────────────────────────────────────────────────────
$payoutRequests = [];
if ($hasPayoutsTable && $dbAvailable) {
    // Known columns in seller_payout_requests per the actual schema.
    $prKnownCols = ['id', 'seller_id', 'amount', 'currency', 'status', 'payout_method',
                    'bank_name', 'bank_account_number', 'bank_account_name', 'promptpay_number',
                    'payment_reference', 'admin_note', 'seller_note',
                    'requested_at', 'approved_at', 'rejected_at', 'paid_at', 'cancelled_at',
                    'updated_at', 'admin_id'];
    $prSel  = [];
    foreach ($prKnownCols as $c) {
        if (column_exists('seller_payout_requests', $c)) { $prSel[] = 'pr.`' . $c . '`'; }
    }

    // Inline seller name from users + seller_applications.
    $prJoinU = '';
    $prJoinA = '';
    if ($hasUsersTable) {
        $prSel[]  = "TRIM(CONCAT(COALESCE(u.first_name,''),' ',COALESCE(u.last_name,''))) AS seller_full_name";
        $prSel[]  = 'u.email AS seller_email';
        $prJoinU  = 'LEFT JOIN users u ON u.id = pr.seller_id';
    }
    if ($hasSellerApps) {
        $prSel[]  = 'sa.farm_name AS seller_farm_name';
        $prJoinA  = 'LEFT JOIN seller_applications sa ON sa.user_id = pr.seller_id';
    }

    if ($prSel) {
        $prWhere  = ['1=1'];
        $prParams = [];
        if ($filterStatus !== '') {
            $prWhere[]  = 'pr.`status` = ?';
            $prParams[] = $filterStatus;
        }
        if ($filterKeyword !== '') {
            $prWhere[]  = '(CAST(pr.`seller_id` AS CHAR) LIKE ? OR CAST(pr.`id` AS CHAR) LIKE ?)';
            $prParams[] = '%' . $filterKeyword . '%';
            $prParams[] = '%' . $filterKeyword . '%';
        }
        $hasReqAt = column_exists('seller_payout_requests', 'requested_at');
        $orderCol = $hasReqAt ? 'pr.`requested_at`' : 'pr.`id`';
        if ($hasReqAt) {
            if ($filterDateFrom !== '') { $prWhere[] = 'pr.`requested_at` >= ?'; $prParams[] = $filterDateFrom . ' 00:00:00'; }
            if ($filterDateTo   !== '') { $prWhere[] = 'pr.`requested_at` <= ?'; $prParams[] = $filterDateTo   . ' 23:59:59'; }
        }
        $prSql = 'SELECT ' . implode(', ', $prSel)
               . ' FROM `seller_payout_requests` pr'
               . ' ' . $prJoinU . ' ' . $prJoinA
               . ' WHERE ' . implode(' AND ', $prWhere)
               . ' ORDER BY ' . $orderCol . ' DESC LIMIT 200';
        $payoutRequests = bv_sp_q($prSql, $prParams);
    }
}

// ── Seller list ───────────────────────────────────────────────────────────────
// Source sellers from seller_balance_entries first; user/application tables are
// optional enrichments only.
$sellers = [];
if ($dbAvailable) {
if ($dbAvailable && $hasLedgerTable) {
    $sSel = ['s.seller_id'];
    $sJoinU = '';
    $sJoinA = ''; 

   if ($hasUsersTable) {
        $sSel[] = column_exists('users', 'email')          ? "COALESCE(u.email,'') AS email"                  : "'' AS email";
        $sSel[] = column_exists('users', 'first_name')     ? "COALESCE(u.first_name,'') AS first_name"        : "'' AS first_name";
        $sSel[] = column_exists('users', 'last_name')      ? "COALESCE(u.last_name,'') AS last_name"          : "'' AS last_name";
        $sSel[] = column_exists('users', 'display_name')   ? "COALESCE(u.display_name,'') AS display_name"    : "'' AS display_name";
        $sSel[] = column_exists('users', 'account_status') ? "COALESCE(u.account_status,'') AS account_status" : "'' AS account_status";
        $sJoinU = 'LEFT JOIN users u ON u.id = s.seller_id';
    } else {
        $sSel[] = "'' AS email";
        $sSel[] = "'' AS first_name";
        $sSel[] = "'' AS last_name";
        $sSel[] = "'' AS display_name";
        $sSel[] = "'' AS account_status";
    }  
   if ($hasSellerApps) {
        $sSel[] = column_exists('seller_applications', 'farm_name')          ? "COALESCE(sa.farm_name,'') AS farm_name" : "'' AS farm_name";
        $sSel[] = column_exists('seller_applications', 'application_status') ? "COALESCE(sa.application_status,'') AS application_status" : "'' AS application_status";
        $sJoinA = 'LEFT JOIN seller_applications sa ON sa.user_id = s.seller_id';
    } else {
        $sSel[] = "'' AS farm_name";
        $sSel[] = "'' AS application_status";
    }

    $sSel[] = "COALESCE((SELECT MAX(NULLIF(sbe2.currency,'')) FROM seller_balance_entries sbe2 WHERE sbe2.seller_id = s.seller_id),'USD') AS currency";

    $sellers = bv_sp_q(
        'SELECT ' . implode(', ', $sSel)
        . ' FROM (SELECT DISTINCT seller_id FROM seller_balance_entries WHERE seller_id IS NOT NULL) s '
        . $sJoinU . ' ' . $sJoinA
        . ' ORDER BY s.seller_id ASC LIMIT 200'
    );	
}

// ── Summary stats ─────────────────────────────────────────────────────────────
$stats = [
    'seller_count'      => count($sellers),
    'pending_requests'  => 0,
    'approved_requests' => 0,
    'paid_payouts'      => 0,
    'total_paid_amount' => 0.0,
    'total_available'   => 0.0,
    'total_pending'     => 0.0,
    'total_locked'      => 0.0,
    'total_paid_out'    => 0.0,
];
if ($hasPayoutsTable && $dbAvailable) {
    foreach (bv_sp_q('SELECT status, COUNT(*) AS cnt, COALESCE(SUM(amount),0) AS tot FROM seller_payout_requests GROUP BY status') as $row) {
        $s = strtolower((string)($row['status'] ?? ''));
        if (in_array($s, ['pending', 'requested'], true)) { $stats['pending_requests'] += (int)$row['cnt']; }
        if ($s === 'approved') { $stats['approved_requests'] += (int)$row['cnt']; }
        if ($s === 'paid')     { $stats['paid_payouts'] += (int)$row['cnt']; $stats['total_paid_amount'] += (float)$row['tot']; }
    }
}
foreach ($sellers as $_sr) {
    $_sid = (int)($_sr['seller_id'] ?? 0);
    if ($_sid <= 0) { continue; }
    $_bal = bv_sp_read_balance($_sid);
    $stats['total_available'] += (float)($_bal['available'] ?? 0);
    $stats['total_pending']   += (float)($_bal['pending'] ?? 0);
    $stats['total_locked']    += (float)($_bal['locked'] ?? 0);
    $stats['total_paid_out']  += (float)($_bal['paid_out'] ?? 0);
}

// ── Recent ledger entries ─────────────────────────────────────────────────────
$ledgerEntries   = [];
$ledgerTableUsed = '';
if ($dbAvailable && $hasLedgerTable) {
    $ledgerEntries = bv_sp_q(
        "SELECT
            id,
            seller_id,
            status AS type,
            source AS balance_type,
            CASE WHEN amount >= 0 THEN 'credit' ELSE 'debit' END AS direction,
            amount,
            0 AS balance_after,
            source AS reference_type,
            COALESCE(order_item_id, order_id, listing_id) AS reference_id,
            hold_reason AS note,
            created_at
         FROM seller_balance_entries
         ORDER BY id DESC
         LIMIT 30"
    );
    $ledgerTableUsed = 'seller_balance_entries';
}

?>
<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Seller Payouts — Admin</title>
<style>
:root{--bg:#f4f5f7;--card:#fff;--border:#dde1e9;--text:#1a1d23;--muted:#6b7280;--accent:#2563eb;--ah:#1d4ed8;--r:6px}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;font-size:14px;background:var(--bg);color:var(--text)}
a{color:var(--accent);text-decoration:none}a:hover{text-decoration:underline}
.page{max-width:1500px;margin:0 auto;padding:24px 20px}
.ph{display:flex;align-items:center;justify-content:space-between;margin-bottom:18px}
.ph h1{font-size:22px;font-weight:700}
.rp{font-size:11px;background:#e0e7ff;color:#3730a3;border-radius:20px;padding:3px 10px;font-weight:600}
.alert{border-radius:var(--r);padding:10px 14px;margin:0 0 10px;font-size:13px;border-left:4px solid}
.a-ok{background:#f0fdf4;border-color:#22c55e}.a-err{background:#fef2f2;border-color:#ef4444}.a-warn{background:#fff7ed;border-color:#fb923c}
.safety{background:#fffbeb;border:2px solid #f59e0b;border-radius:var(--r);padding:12px 16px;margin-bottom:18px}
.safety strong{color:#92400e}
.cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:11px;margin-bottom:22px}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:12px 14px}
.cl{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:4px}
.cv{font-size:18px;font-weight:700}
.cw{color:#d97706}.cg{color:#16a34a}.ci{color:var(--accent)}.cp{color:#7c3aed}
.panel{background:var(--card);border:1px solid var(--border);border-radius:var(--r);margin-bottom:22px}
.ph2{padding:10px 14px;border-bottom:1px solid var(--border);display:flex;align-items:center;justify-content:space-between}
.ph2 h2{font-size:15px;font-weight:600}
.pb{padding:12px 14px}
.fr{display:flex;flex-wrap:wrap;gap:6px;align-items:flex-end;margin-bottom:10px}
.fr input,.fr select{padding:5px 8px;border:1px solid var(--border);border-radius:var(--r);font-size:13px}
.fr .bf{padding:5px 12px;background:var(--accent);color:#fff;border:none;border-radius:var(--r);cursor:pointer;font-size:13px}
.fr .br{padding:5px 10px;background:#f3f4f6;color:#374151;border:1px solid #d1d5db;border-radius:var(--r);cursor:pointer;font-size:13px;text-decoration:none}
.tw{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th{background:#f8f9fb;font-weight:600;text-align:left;padding:7px 8px;border-bottom:2px solid var(--border);white-space:nowrap}
td{padding:6px 8px;border-bottom:1px solid var(--border);vertical-align:top}
tr:last-child td{border-bottom:none}tr:hover td{background:#f9fafb}
.badge{display:inline-block;padding:2px 7px;border-radius:20px;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.04em}
.badge-success{background:#dcfce7;color:#15803d}.badge-danger{background:#fee2e2;color:#b91c1c}
.badge-warning{background:#fef9c3;color:#92400e}.badge-secondary{background:#e5e7eb;color:#374151}
.ac{display:flex;flex-wrap:wrap;gap:4px;align-items:flex-start}
.btn{display:inline-flex;align-items:center;padding:4px 9px;border-radius:var(--r);border:1px solid transparent;font-size:12px;cursor:pointer;font-weight:500;white-space:nowrap;background:none}
.b-ok{background:#22c55e;color:#fff;border-color:#16a34a}.b-ok:hover{background:#16a34a}
.b-ng{background:#ef4444;color:#fff;border-color:#dc2626}.b-ng:hover{background:#dc2626}
.b-pay{background:var(--accent);color:#fff;border-color:var(--ah)}.b-pay:hover{background:var(--ah)}
.b-sec{background:#f3f4f6;color:#374151;border-color:#d1d5db}.b-sec:hover{background:#e5e7eb}
.btn[disabled]{opacity:.45;cursor:not-allowed;pointer-events:none}
.ig{display:flex;flex-wrap:wrap;gap:3px;align-items:center}
.ig input[type=text],.ig select{padding:3px 6px;border:1px solid var(--border);border-radius:var(--r);font-size:12px}
.ig input[type=text]{width:125px}
.fg{display:grid;grid-template-columns:repeat(auto-fill,minmax(185px,1fr));gap:10px}
.fgr{display:flex;flex-direction:column;gap:3px}
.fgr label{font-size:12px;font-weight:600;color:var(--muted)}
.fgr input,.fgr select,.fgr textarea{padding:6px 8px;border:1px solid var(--border);border-radius:var(--r);font-size:13px}
.fgr textarea{resize:vertical;min-height:50px}
.bp{background:var(--accent);color:#fff;border:none;border-radius:var(--r);padding:7px 15px;font-size:13px;cursor:pointer;font-weight:600;margin-top:10px}
.bp:hover{background:var(--ah)}
.empty{color:var(--muted);text-align:center;padding:22px;font-style:italic}
.sql-box{background:#1e1e2e;color:#cdd6f4;font-family:'Consolas','Courier New',monospace;font-size:11px;padding:12px;border-radius:var(--r);overflow-x:auto;margin-top:8px;white-space:pre}
details summary{cursor:pointer;font-weight:600;font-size:13px;color:var(--accent);margin-top:6px}
</style>
</head>
<body>
<div class="page">

<div class="ph">
    <h1>&#127968; Seller Payouts &mdash; Admin</h1>
    <span class="rp"><?php echo h(strtoupper(bv_sp_get_role() ?: 'ADMIN')); ?></span>
</div>

<div class="safety">
    <strong>&#9888;&#65039; Internal Workflow Only</strong><br>
    This page manages internal payout workflow only. It does <strong>not</strong> send money externally.
    Use <em>Mark Paid</em> only <strong>after confirming</strong> the seller has received money manually outside the system.
</div>

<?php foreach ($messages as $msg): ?><div class="alert a-ok">&#9989; <?php echo h($msg); ?></div><?php endforeach; ?>
<?php foreach ($errors   as $err): ?><div class="alert a-err">&#10060; <?php echo h($err); ?></div><?php endforeach; ?>
<?php if (!$dbAvailable): ?><div class="alert a-err">&#128308; <strong>Database unavailable.</strong> bv_sp_pdo() returned null. Check that $pdo/$db global is set, or that the helper's bv_seller_balance_pdo() is reachable.</div><?php endif; ?>
<?php if (!$sbAvailable): ?><div class="alert a-warn">&#9888;&#65039; <strong>seller_balance.php helper not found.</strong> All mutation actions are disabled.</div><?php endif; ?>

<!-- Cards -->
<div class="cards">
    <div class="card"><div class="cl">Sellers</div><div class="cv"><?php echo (int)$stats['seller_count']; ?></div></div>
    <div class="card"><div class="cl">Total Available</div><div class="cv cg"><?php echo h(money_fmt($stats['total_available'])); ?></div></div>
    <div class="card"><div class="cl">Total Pending</div><div class="cv cw"><?php echo h(money_fmt($stats['total_pending'])); ?></div></div>
    <div class="card"><div class="cl">Total Locked</div><div class="cv cp"><?php echo h(money_fmt($stats['total_locked'])); ?></div></div>
    <div class="card"><div class="cl">Total Paid Out</div><div class="cv cg"><?php echo h(money_fmt($stats['total_paid_out'])); ?></div></div>
    <div class="card"><div class="cl">Pending Requests</div><div class="cv cw"><?php echo (int)$stats['pending_requests']; ?></div></div>
    <div class="card"><div class="cl">Approved</div><div class="cv ci"><?php echo (int)$stats['approved_requests']; ?></div></div>
    <div class="card"><div class="cl">Paid Payouts</div><div class="cv cg"><?php echo (int)$stats['paid_payouts']; ?></div></div>
    <div class="card"><div class="cl">Paid Out Total</div><div class="cv cg"><?php echo h(money_fmt($stats['total_paid_amount'])); ?></div></div>
</div>

<!-- Payout Requests -->
<div class="panel">
    <div class="ph2">
        <h2>Payout Requests</h2>
        <?php if (!$hasPayoutsTable): ?><span class="badge badge-danger">Table missing</span>
        <?php else: ?><span class="badge badge-secondary"><?php echo count($payoutRequests); ?> rows</span><?php endif; ?>
    </div>
    <div class="pb">
    <?php if (!$hasPayoutsTable): ?>
        <div class="alert a-warn"><strong>seller_payout_requests table is missing.</strong> Create this table to enable the payout request workflow.</div>
        <details>
            <summary>&#9654; Show CREATE TABLE SQL (copy &amp; run in phpMyAdmin / MySQL CLI)</summary>
            <div class="sql-box">CREATE TABLE IF NOT EXISTS `seller_payout_requests` (
  `id` BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `seller_id` BIGINT UNSIGNED NOT NULL,
  `amount` DECIMAL(12,2) NOT NULL DEFAULT 0.00,
  `currency` CHAR(3) NOT NULL DEFAULT 'USD',
  `status` ENUM('requested','pending','approved','paid','rejected','cancelled','failed') NOT NULL DEFAULT 'requested',
  `payout_method` VARCHAR(50) DEFAULT NULL,
  `payment_reference` VARCHAR(120) DEFAULT NULL,
  `seller_note` TEXT DEFAULT NULL,
  `admin_note` TEXT DEFAULT NULL,
  `requested_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `approved_at` DATETIME DEFAULT NULL,
  `rejected_at` DATETIME DEFAULT NULL,
  `paid_at` DATETIME DEFAULT NULL,
  `cancelled_at` DATETIME DEFAULT NULL,
  `updated_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  `admin_id` BIGINT UNSIGNED DEFAULT NULL,
  PRIMARY KEY (`id`),
  KEY `idx_spr_seller_id`    (`seller_id`),
  KEY `idx_spr_status`       (`status`),
  KEY `idx_spr_requested_at` (`requested_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;</div>
        </details>
    <?php else: ?>
        <form method="get" action="seller_payouts.php">
        <div class="fr">
            <input type="text" name="keyword" placeholder="Seller ID / Request ID" value="<?php echo h($filterKeyword); ?>">
            <select name="status">
                <option value="">All Statuses</option>
                <?php foreach (['pending','requested','approved','paid','rejected','cancelled','failed'] as $_s): ?>
                    <option value="<?php echo h($_s); ?>" <?php echo $filterStatus === $_s ? 'selected' : ''; ?>><?php echo ucfirst($_s); ?></option>
                <?php endforeach; ?>
            </select>
            <input type="date" name="date_from" value="<?php echo h($filterDateFrom); ?>">
            <input type="date" name="date_to"   value="<?php echo h($filterDateTo); ?>">
            <button type="submit" class="bf">Filter</button>
            <a href="seller_payouts.php" class="br">Reset</a>
        </div>
        </form>

        <?php if (!$payoutRequests): ?><p class="empty">No payout requests match the filter.</p>
        <?php else: ?>
        <div class="tw"><table>
        <thead><tr><th>ID</th><th>Seller</th><th>Amount</th><th>Currency</th><th>Method</th><th>Status</th><th>Requested At</th><th>Updated At</th><th>Payment Ref</th><th>Admin Note</th><th>Actions</th></tr></thead>
        <tbody>
        <?php foreach ($payoutRequests as $_r):
            $_st  = strtolower((string)($_r['status'] ?? ''));
            $_rid = (int)($_r['id'] ?? 0);
            $_cur = (string)($_r['currency'] ?? 'USD');
            $_fin = in_array($_st, ['paid','rejected','cancelled','failed'], true);
            $_da  = $_r['requested_at'] ?? '';
            $_du  = $_r['updated_at'] ?? $_r['paid_at'] ?? $_r['rejected_at'] ?? '';
            $_sl  = trim((string)($_r['seller_farm_name'] ?? ''));
            if ($_sl === '') { $_sl = trim((string)($_r['seller_full_name'] ?? '')); }
            if ($_sl === '') { $_sl = (string)($_r['seller_email'] ?? 'Seller #' . $_r['seller_id']); }
        ?><tr>
            <td><strong>#<?php echo h($_rid); ?></strong></td>
            <td><?php echo h($_sl); ?><small style="color:var(--muted);display:block">#<?php echo h($_r['seller_id'] ?? ''); ?></small></td>
            <td><?php echo h(money_fmt($_r['amount'] ?? 0, $_cur)); ?></td>
            <td><?php echo h($_cur); ?></td>
            <td><?php echo h($_r['payout_method'] ?? '&mdash;'); ?></td>
            <td><span class="badge <?php echo h(status_badge_class($_st)); ?>"><?php echo h($_st ?: 'unknown'); ?></span></td>
            <td><?php echo h($_da ? date('d M Y H:i', strtotime($_da)) : '&mdash;'); ?></td>
            <td><?php echo h($_du ? date('d M Y H:i', strtotime($_du)) : '&mdash;'); ?></td>
            <td><?php echo h($_r['payment_reference'] ?? '&mdash;'); ?></td>
            <td><?php echo h(mb_strimwidth((string)($_r['admin_note'] ?? ''), 0, 50, '&hellip;') ?: '&mdash;'); ?></td>
            <td class="ac">
            <?php if (in_array($_st, ['pending','requested'], true)): ?>
                <?php if ($hasApprove): ?>
                <form method="post" action="seller_payouts.php" onsubmit="return confirm('Approve payout #<?php echo (int)$_rid; ?>?');">
                    <input type="hidden" name="csrf_token" value="<?php echo h($_csrfToken); ?>">
                    <input type="hidden" name="action"     value="approve_request">
                    <input type="hidden" name="request_id" value="<?php echo h($_rid); ?>">
                    <button type="submit" class="btn b-ok">Approve</button>
                </form>
                <?php else: ?><button class="btn b-ok" disabled title="Helper missing">Approve</button><?php endif; ?>
                <?php if ($hasReject): ?>
                <form method="post" action="seller_payouts.php" onsubmit="return confirm('Reject payout #<?php echo (int)$_rid; ?>?');">
                    <input type="hidden" name="csrf_token"  value="<?php echo h($_csrfToken); ?>">
                    <input type="hidden" name="action"      value="reject_request">
                    <input type="hidden" name="request_id"  value="<?php echo h($_rid); ?>">
                    <span class="ig">
                        <input type="text" name="admin_note" placeholder="Reason (required)" required maxlength="255">
                        <button type="submit" class="btn b-ng">Reject</button>
                    </span>
                </form>
                <?php else: ?><button class="btn b-ng" disabled title="Helper missing">Reject</button><?php endif; ?>
            <?php elseif ($_st === 'approved'): ?>
                <?php if ($hasMarkPaid): ?>
                <form method="post" action="seller_payouts.php" onsubmit="return confirm('Mark #<?php echo (int)$_rid; ?> as PAID?\nOnly after seller has received money externally.');">
                    <input type="hidden" name="csrf_token"  value="<?php echo h($_csrfToken); ?>">
                    <input type="hidden" name="action"      value="mark_paid">
                    <input type="hidden" name="request_id"  value="<?php echo h($_rid); ?>">
                    <span class="ig">
                        <input type="text" name="payment_reference" placeholder="Ref (required)" required maxlength="160">
                        <select name="payment_method" style="padding:3px 5px;border:1px solid var(--border);border-radius:var(--r);font-size:12px">
                            <option value="manual">Manual</option>
                            <option value="bank_transfer">Bank Transfer</option>
                            <option value="promptpay">PromptPay</option>
                            <option value="wise">Wise</option>
                            <option value="other">Other</option>
                        </select>
                        <input type="text" name="admin_note" placeholder="Note (optional)" maxlength="255">
                        <button type="submit" class="btn b-pay">Mark Paid</button>
                    </span>
                </form>
                <?php elseif (!$isSuperAdmin): ?><span style="font-size:11px;color:var(--muted)">Superadmin only</span>
                <?php else: ?><button class="btn b-pay" disabled title="Helper missing">Mark Paid</button><?php endif; ?>
            <?php else: ?>
                <span class="badge <?php echo h(status_badge_class($_st)); ?>"><?php echo h($_st ?: 'unknown'); ?></span>
            <?php endif; ?>
            </td>
        </tr><?php endforeach; ?>
        </tbody></table></div>
        <?php endif; ?>
    <?php endif; ?>
    </div>
</div>

<!-- Seller Balances -->
<div class="panel">
    <div class="ph2">
        <h2>Seller Balances</h2>
        <?php if (!function_exists('bv_seller_balance_get')): ?>
            <span class="badge badge-warning">Snapshot only</span>
        <?php endif; ?>
    </div>
    <div class="pb">
    <?php if (!function_exists('bv_seller_balance_get')): ?>
        <div class="alert a-warn" style="margin-bottom:10px">&#9888;&#65039; <code>bv_seller_balance_get()</code> not found. Showing best-effort values from seller_balances snapshot. Do not use for mutation decisions.</div>
    <?php endif; ?>
    <?php if (!$sellers): ?>
        <p class="empty">No seller records found.<?php if (!$dbAvailable): ?> (Database unavailable.)<?php endif; ?></p>
    <?php else: ?>
    <div class="tw"><table>
    <thead><tr><th>Seller</th><th>Available</th><th>Pending</th><th>Held/Locked</th><th>Paid Out</th><th>Total Earned</th><th>App Status</th><th>Actions</th></tr></thead>
    <tbody>
    <?php foreach ($sellers as $_s):
        $_sid  = (int)($_s['seller_id'] ?? 0);
        $_cur  = (string)($_s['currency'] ?? 'USD');
        $_lbl  = seller_label($_s);
        // Use bv_sp_read_balance which tries helper first then snapshot.
        $_bal  = bv_sp_read_balance($_sid);
        // If helper returned zeros, prefer the snapshot columns we already fetched.
        if ($_bal['available'] + $_bal['pending'] + $_bal['paid_out'] + $_bal['total'] == 0.0
            && isset($_s['available_balance'])) {
            $_bal = [
                'available' => (float)($_s['available_balance']  ?? 0),
                'pending'   => max(0.0, (float)($_s['pending_balance'] ?? 0)),
                'locked'    => (float)($_s['held_balance']        ?? 0),
                'paid_out'  => (float)($_s['paid_out_balance']    ?? 0),
                'total'     => (float)($_s['total_earned_gross']  ?? 0),
                'currency'  => $_cur,
            ];
        }
        $_pend = (float)($_bal['pending'] ?? 0);
        $_appSt = (string)($_s['application_status'] ?? '');
    ?><tr>
        <td>
            <?php echo h($_lbl); ?>
            <small style="color:var(--muted);display:block">#<?php echo h($_sid); ?><?php if (!empty($_s['email'])): ?> &middot; <?php echo h($_s['email']); ?><?php endif; ?></small>
        </td>
        <td><?php echo h(money_fmt($_bal['available'], $_cur)); ?></td>
        <td><?php echo h(money_fmt($_bal['pending'],   $_cur)); ?></td>
        <td><?php echo h(money_fmt($_bal['locked'],    $_cur)); ?></td>
        <td><?php echo h(money_fmt($_bal['paid_out'],  $_cur)); ?></td>
        <td><?php echo h(money_fmt($_bal['total'],     $_cur)); ?></td>
        <td><?php if ($_appSt): ?><span class="badge <?php echo h(status_badge_class($_appSt)); ?>"><?php echo h($_appSt); ?></span><?php else: ?>&mdash;<?php endif; ?></td>
        <td class="ac">
            <?php if ($hasReleasePending): ?>
            <form method="post" action="seller_payouts.php"
                  onsubmit="return confirm('Release <?php echo h(money_fmt($_pend, $_cur)); ?> pending for seller #<?php echo (int)$_sid; ?>?');">
                <input type="hidden" name="csrf_token" value="<?php echo h($_csrfToken); ?>">
                <input type="hidden" name="action"     value="release_pending">
                <input type="hidden" name="seller_id"  value="<?php echo h($_sid); ?>">
                <button type="submit" class="btn b-sec" <?php echo $_pend > 0 ? '' : 'disabled'; ?>>
                    Release<?php if ($_pend > 0): ?> (<?php echo h(money_fmt($_pend, $_cur)); ?>)<?php endif; ?>
                </button>
            </form>
            <?php endif; ?>
        </td>
    </tr><?php endforeach; ?>
    </tbody></table></div>
    <?php endif; ?>
    </div>
</div>

<!-- Adjust Balance -->
<?php if ($hasAdjustBalance): ?>
<div class="panel">
    <div class="ph2"><h2>Adjust Balance</h2><span class="badge badge-warning">Superadmin only</span></div>
    <div class="pb">
        <form method="post" action="seller_payouts.php">
            <input type="hidden" name="csrf_token" value="<?php echo h($_csrfToken); ?>">
            <input type="hidden" name="action"     value="adjust_balance">
            <div class="fg">
                <div class="fgr"><label>Seller ID</label><input type="number" name="seller_id" min="1" required placeholder="e.g. 5"></div>
                <div class="fgr"><label>Amount (positive)</label><input type="number" name="amount" step="0.01" min="0.01" required placeholder="e.g. 50.00"></div>
                <div class="fgr"><label>Direction</label><select name="direction" required><option value="credit">Credit (add)</option><option value="debit">Debit (subtract)</option></select></div>
                <div class="fgr"><label>Admin Note (required)</label><textarea name="admin_note" required placeholder="Reason for adjustment"></textarea></div>
            </div>
            <button type="submit" class="bp" onclick="return confirm('Apply balance adjustment? This cannot be undone.');">Apply Adjustment</button>
        </form>
    </div>
</div>
<?php elseif ($sbAvailable): ?>
    <div class="alert a-warn" style="margin-bottom:22px">&#9888;&#65039; Adjust Balance hidden &mdash; <code>bv_seller_balance_admin_adjust()</code> not found or role insufficient.</div>
<?php endif; ?>

<!-- Ledger -->
<?php if ($ledgerEntries || $dbAvailable): ?>
<div class="panel">
    <div class="ph2">
        <h2>Recent Ledger Entries</h2>
        <span style="font-size:12px;color:var(--muted)"><?php echo h($ledgerTableUsed ?: 'seller_balance_entries'); ?> &mdash; last 30 rows (read-only)</span>
    </div>
    <div class="pb">
    <?php if (!$ledgerEntries): ?>
       <p class="empty">No ledger entries<?php echo $dbAvailable ? ' found in seller_balance_entries.' : ' (DB unavailable).'; ?></p>
    <?php else: ?>
    <div class="tw"><table>
    <thead><tr><th>ID</th><th>Seller</th><th>Type</th><th>Dir</th><th>Amount</th><th>Bal After</th><th>Ref Type</th><th>Ref ID</th><th>Note</th><th>Date</th></tr></thead>
    <tbody>
    <?php foreach ($ledgerEntries as $_e):
        $_dir = strtolower((string)($_e['direction'] ?? ''));
    ?><tr>
        <td><?php echo h($_e['id'] ?? ''); ?></td>
        <td><?php echo h($_e['seller_id'] ?? ''); ?></td>
        <td><code style="font-size:11px"><?php echo h($_e['type'] ?? ''); ?></code><?php if (!empty($_e['balance_type'])): ?> <small style="color:var(--muted)">(<?php echo h($_e['balance_type']); ?>)</small><?php endif; ?></td>
        <td><span style="color:<?php echo $_dir === 'credit' ? '#16a34a' : '#dc2626'; ?>;font-weight:600"><?php echo h($_dir ?: '&mdash;'); ?></span></td>
        <td><?php echo h(money_fmt($_e['amount'] ?? 0)); ?></td>
        <td><?php echo h(money_fmt($_e['balance_after'] ?? 0)); ?></td>
        <td><?php echo h($_e['reference_type'] ?? '&mdash;'); ?></td>
        <td><?php echo h($_e['reference_id'] ?? '&mdash;'); ?></td>
        <td><?php echo h(mb_strimwidth((string)($_e['note'] ?? ''), 0, 48, '&hellip;') ?: '&mdash;'); ?></td>
        <td style="white-space:nowrap;font-size:12px"><?php echo h($_e['created_at'] ?? '&mdash;'); ?></td>
    </tr><?php endforeach; ?>
    </tbody></table></div>
    <?php endif; ?>
    </div>
</div>
<?php endif; ?>

</div><!-- .page -->
</body>
</html>
