<?php
// Production: Disable error display
define('DEBUG', false);
ini_set('display_errors', 0);
error_reporting(0);

// Security headers
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Content-Security-Policy: default-src 'self'");

session_start();

// Theme Cookie: if not set in session, load from cookie (default dark)
if (!isset($_SESSION['theme'])) {
    if (isset($_COOKIE['theme'])) {
        $_SESSION['theme'] = $_COOKIE['theme'];
    } else {
        $_SESSION['theme'] = 'dark';
        setcookie('theme', 'dark', time() + (3600 * 24 * 30));
    }
}

// Configuration
$session_timeout = 1800; // 30 minutes
$session_log = 'sessions.txt';
$user_file = 'users.txt';
$lm_api_url = "http://server.example.com:1234";

// Function to fetch models from the API endpoint for model selection
function fetch_models() {
    $url = "http://server.example.com:1234/api/v0/models";
    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10,
        CURLOPT_CONNECTTIMEOUT => 5
    ]);
    $response = curl_exec($ch);
    if (curl_errno($ch)) {
        // In case of error, return an empty array so the dropdown can be empty or fallback static value.
        curl_close($ch);
        return [];
    }
    curl_close($ch);
    $data = json_decode($response, true);
    if (isset($data['data']) && is_array($data['data'])) {
        return $data['data'];
    }
    return [];
}

// Fetch models once for dropdowns
$models = fetch_models();

// Get client IP address
function get_client_ip() {
    $ip_keys = ['HTTP_CLIENT_IP', 'HTTP_X_FORWARDED_FOR', 'HTTP_X_FORWARDED', 'HTTP_X_CLUSTER_CLIENT_IP', 'HTTP_FORWARDED_FOR', 'HTTP_FORWARDED', 'REMOTE_ADDR'];
    foreach ($ip_keys as $key) {
        if (array_key_exists($key, $_SERVER) === true) {
            foreach (explode(',', $_SERVER[$key]) as $ip) {
                $ip = trim($ip);
                if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) !== false) {
                    return $ip;
                }
            }
        }
    }
    return $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
}

// Chat log file per user (persistent across sessions)
function chat_log_file($user) {
    return "logs/" . preg_replace('/[^A-Za-z0-9_\-]/', '_', $user) . ".txt";
}

// Create required directories
if (!is_dir('logs')) {
    if (!mkdir('logs', 0755, true)) {
        die('Failed to create logs directory');
    }
}

// Generate CSRF token before any output
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Handle logout request (invalidate session)
if (isset($_GET['logout'])) {
    session_unset();
    session_destroy();
    header("Location: /");
    exit;
}

// Handle clear chat request (persistent across logins)
if (isset($_GET['clear_chat'])) {
    $clearTime = time();
    $_SESSION['chat_cleared_at'] = $clearTime;
    if (isset($_SESSION['user'])) {
        $clearFile = "logs/" . preg_replace('/[^A-Za-z0-9_\-]/', '_', $_SESSION['user']) . "_clear.txt";
        file_put_contents($clearFile, $clearTime);
    }
    // Also log the clear event in session log
    file_put_contents($session_log, sprintf(
        "%s|%s|%s|CLEAR_CHAT|%s\n",
        $_SESSION['user'] ?? 'unknown',
        session_id(),
        get_client_ip(),
        $clearTime
    ), FILE_APPEND);
    header("Location: " . strtok($_SERVER['REQUEST_URI'], '?'));
    exit;
}

// Handle theme update requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['update_theme'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        http_response_code(403);
        die('CSRF validation failed');
    }
    $newTheme = $_POST['update_theme'];
    if (in_array($newTheme, ['light', 'dark'])) {
        $_SESSION['theme'] = $newTheme;
        // Also store theme in a cookie (30 days)
        setcookie('theme', $newTheme, time() + (3600 * 24 * 30));
    }
    header('Content-Type: application/json');
    echo json_encode(['status' => 'success', 'theme' => $newTheme]);
    exit;
}

// CSRF Protection for other POST requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && !isset($_POST['update_theme'])) {
    if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
        die('CSRF token validation failed');
    }
}

function validate_token($token) {
    global $user_file;
    if (!file_exists($user_file)) return false;
    $lines = file($user_file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    foreach ($lines as $line) {
        $parts = explode(":", trim($line));
        if (count($parts) === 2 && $parts[1] === $token) {
            return $parts[0];
        }
    }
    return false;
}

function session_expired() {
    global $session_timeout;
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity']) > $session_timeout) {
        return true;
    }
    $_SESSION['last_activity'] = time();
    return false;
}

// Handle login
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['token'])) {
    $user = validate_token($_POST['token']);
    if ($user) {
        $_SESSION['user'] = $user;
        // Set default model from POST if provided; otherwise default to first model from dynamic list if available or fallback
        if (isset($_POST['model']) && $_POST['model'] != "") {
            $_SESSION['model'] = $_POST['model'];
        } elseif (!empty($models)) {
            $_SESSION['model'] = $models[0]['id'];
        } else {
            $_SESSION['model'] = 'deepseek-coder-33b-instruct';
        }
        // Default theme remains from cookie (or dark if none)
        // Load persistent clear marker if exists
        $clearFile = "logs/" . preg_replace('/[^A-Za-z0-9_\-]/', '_', $user) . "_clear.txt";
        if (file_exists($clearFile)) {
            $_SESSION['chat_cleared_at'] = (int)file_get_contents($clearFile);
        }
        // Load chat history
        $logFile = chat_log_file($user);
        $fullHistory = file_exists($logFile) ? json_decode(file_get_contents($logFile), true) : [];
        if (isset($_SESSION['chat_cleared_at'])) {
            $clearTime = $_SESSION['chat_cleared_at'];
            $fullHistory = array_filter($fullHistory, function($msg) use ($clearTime) {
                return $msg['time'] >= $clearTime;
            });
        }
        $_SESSION['chat'] = $fullHistory;
        // Log session with IP and model
        $ip = get_client_ip();
        file_put_contents($session_log, sprintf(
            "%s|%s|%s|%s\n",
            $user,
            session_id(),
            $ip,
            $_SESSION['model']
        ), FILE_APPEND);
        header("Location: /");
        exit;
    } else {
        $error = "Invalid token.";
    }
}

// Handle session expiration
if (session_expired()) {
    session_unset();
    session_destroy();
    header("Location: /");
    exit;
}

// Handle chat submission
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['prompt'], $_POST['model'])) {
    $model = trim($_POST['model']);
    $prompt = trim($_POST['prompt']);
    $ip = get_client_ip();
    
    // Use chat completions for models of type LLM, otherwise fallback
    $chatModels = array_column($models, 'id'); // Use dynamic model list IDs
    if (in_array($model, $chatModels)) {
        $apiEndpoint = "$lm_api_url/v1/chat/completions";
        $payload = [
            "model" => $model,
            "messages" => [
                ["role" => "user", "content" => $prompt]
            ],
            "temperature" => 0.7,
            "stream" => false
        ];
    } else {
        $apiEndpoint = "$lm_api_url/v1/completions";
        $payload = [
            "prompt" => $prompt,
            "max_tokens" => 500,
            "temperature" => 0.7,
            "stop" => null
        ];
    }
    
    $ch = curl_init($apiEndpoint);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_POSTFIELDS => json_encode($payload),
        CURLOPT_HTTPHEADER => ["Content-Type: application/json"],
        CURLOPT_TIMEOUT => 30,
        CURLOPT_CONNECTTIMEOUT => 10
    ]);
    
    $response = curl_exec($ch);
    if (curl_errno($ch)) {
        $curlError = curl_error($ch);
        error_log("API Error: " . $curlError);
        $reply = DEBUG ? "API Error: $curlError" : "Service temporarily unavailable. Please try again later.";
    } else {
        $json = json_decode($response, true);
        if (isset($json['choices'][0]['message']['content'])) {
            $reply = $json['choices'][0]['message']['content'];
        } elseif (isset($json['choices'][0]['text'])) {
            $reply = $json['choices'][0]['text'];
        } else {
            error_log("API Response Error: " . $response);
            $reply = DEBUG ? "API Response Error: " . $response : "Model not available or service error.";
        }
    }
    curl_close($ch);
    
    $timestamp = time();
    $newMessage = [
        "time" => $timestamp,
        "model" => $model,
        "ip" => $ip,
        "you" => $prompt,
        "intelligencE&" => $reply
    ];
    
    $_SESSION['chat'][] = $newMessage;
    
    $logFile = chat_log_file($_SESSION['user']);
    $history = file_exists($logFile) ? json_decode(file_get_contents($logFile), true) : [];
    $history[] = $newMessage;
    file_put_contents($logFile, json_encode($history));
    
    header("Location: " . $_SERVER['REQUEST_URI']);
    exit;
}
?>

<?php if (!isset($_SESSION['user'])): ?>
<!-- Login Form -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <!-- Standard viewport meta tag -->
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>intelligencE& AI</title>
    <style>
        :root { --eamp-color: #800000; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            display: flex; 
            justify-content: center; 
            align-items: center;
            height: 100vh; 
            margin: 0; 
            background: #f5f7fa;
        }
        .login-container {
            background: white; 
            padding: 2rem; 
            border-radius: 8px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1); 
            width: 100%; 
            max-width: 400px;
        }
        .form-group { margin-bottom: 1.5rem; }
        label { display: block; margin-bottom: 0.5rem; font-weight: 600; color: #333; }
        input, select { width: 100%; padding: 0.75rem; border: 1px solid #ddd; border-radius: 4px; font-size: 1rem; box-sizing: border-box; }
        button { width: 100%; padding: 0.75rem; background-color: #4CAF50; color: white;
                  border: none; border-radius: 4px; font-size: 1rem; cursor: pointer; transition: background-color 0.3s; }
        button:hover { background-color: #45a049; }
        .error { color: #e74c3c; margin-top: 1rem; text-align: center; }
    </style>
</head>
<body>
    <div class="login-container">
        <h2 style="text-align: center; margin-bottom: 1.5rem;">
            intelligenc<span style="color: var(--eamp-color);">E&</span> AI
        </h2>
        <form method="POST">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
            <div class="form-group">
                <label for="token">Access Token</label>
                <input type="password" id="token" name="token" required>
            </div>
            <div class="form-group">
                <label for="model">Model</label>
                <select id="model" name="model" required>
                    <?php
                    // Populate dropdown options dynamically from fetched models
                    if (!empty($models)) {
                        foreach ($models as $modelData) {
                            // Only include models of type "llm" (if needed, adjust filtering as desired)
                            if ($modelData['type'] === 'llm') {
                                $selected = (isset($_SESSION['model']) && $_SESSION['model'] === $modelData['id']) ? 'selected' : '';
                                echo '<option value="' . htmlspecialchars($modelData['id']) . '" ' . $selected . '>' . htmlspecialchars($modelData['id']) . '</option>';
                            }
                        }
                    } else {
                        // Fallback option if fetching models fails
                        echo '<option value="deepseek-coder-33b-instruct">deepseek-coder-33b-instruct</option>';
                    }
                    ?>
                </select>
            </div>
            <button type="submit">Login</button>
            <?php if (!empty($error)): ?>
                <p class="error"><?= htmlspecialchars($error) ?></p>
            <?php endif; ?>
        </form>
    </div>
</body>
</html>
<?php exit; endif; ?>

<!-- Main Chat Interface -->
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <!-- Standard viewport meta tag -->
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>intelligencE& AI</title>
    <style>
        :root {
            --light-bg: #f5f7fa;
            --dark-bg: #1a1a1a;
            --light-text: #333;
            --dark-text: #f0f0f0;
            --primary: #4CAF50;
            --primary-hover: #45a049;
            --eamp-color: #800000;
            --user-box-bg: #e0e0e0;
            --dark-user-box-bg: #333;
        }
        .page-wrapper {
            /* Fluid responsive design; no fixed scaling */
        }
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            transition: background-color 0.3s ease, color 0.3s ease;
        }
        .dark {
            background-color: var(--dark-bg);
            color: var(--dark-text);
        }
        .light {
            background-color: var(--light-bg);
            color: var(--light-text);
        }
        .chat-container {
            max-width: 900px;
            margin: 0 auto;
            padding: 20px;
            padding-bottom: 100px; /* space for fixed footer */
            min-height: 100vh;
            box-sizing: border-box;
        }
        .chat-header {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 1px solid #ddd;
            position: relative;
        }
        .dark .chat-header {
            border-bottom-color: #444;
        }
        .chat-header .title {
            font-size: 1.5rem;
            font-weight: bold;
        }
        .chat-header .title span {
            color: var(--eamp-color);
        }
        .chat-header .actions {
            display: flex;
            align-items: center;
            gap: 10px;
            width: 100%;
            justify-content: flex-end;
        }
        /* User box as dropdown container */
        .user-box {
            background-color: var(--user-box-bg);
            padding: 0.5rem 1rem;
            border-radius: 4px;
            cursor: pointer;
            font-weight: bold;
            position: relative;
        }
        .dark .user-box {
            background-color: var(--dark-user-box-bg);
            color: white;
        }
        /* Dropdown menu hidden by default */
        .user-dropdown {
            display: none;
            position: absolute;
            top: 100%;
            left: 0;
            background: inherit;
            border: 1px solid #ddd;
            border-radius: 4px;
            z-index: 10;
            width: 100%;
        }
        .user-dropdown a {
            display: block;
            padding: 0.5rem 1rem;
            text-decoration: none;
            color: inherit;
            background: rgba(52, 152, 219, 0.8);
            transition: background 0.2s;
            text-align: center;
        }
        .user-dropdown a:hover {
            background: rgba(52, 152, 219, 1);
        }
        /* Show dropdown on hover */
        .user-box:hover .user-dropdown {
            display: block;
        }
        /* Desktop: action buttons in header (Clear, Logout) */
        .chat-header a.clear-chat,
        .chat-header a.logout {
            padding: 0.5rem 1rem;
            font-size: 1rem;
            border-radius: 4px;
            text-decoration: none;
            color: white;
            transition: background-color 0.2s;
        }
        .chat-header a.clear-chat {
            background-color: #f39c12;
            text-transform: lowercase;
        }
        .chat-header a.clear-chat:hover {
            background-color: #e67e22;
        }
        .chat-header a.logout {
            background-color: #e74c3c;
            display: inline-flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
        }
        .chat-header a.logout:hover {
            transform: scale(1.05);
        }
        .chat-header a.logout svg {
            width: 24px;
            height: 24px;
        }
        .chat-messages {
            display: flex;
            flex-direction: column;
            gap: 15px;
            max-height: 60vh;
            overflow-y: auto;
            padding-right: 10px;
        }
        /* Scrollbar styling */
        .chat-messages::-webkit-scrollbar {
            width: 8px;
        }
        .chat-messages::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 4px;
        }
        .chat-messages::-webkit-scrollbar-thumb {
            background: #888;
            border-radius: 4px;
        }
        .chat-messages::-webkit-scrollbar-thumb:hover {
            background: #555;
        }
        .dark .chat-messages::-webkit-scrollbar-track {
            background: #333;
        }
        .dark .chat-messages::-webkit-scrollbar-thumb {
            background: #666;
        }
        .message {
            padding: 15px;
            border-radius: 8px;
            animation: fadeIn 0.3s ease-out;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .dark .message {
            box-shadow: 0 2px 4px rgba(0,0,0,0.3);
        }
        .user-message {
            background-color: #e3f2fd;
            color: #0d47a1;
            align-self: flex-end;
            max-width: 80%;
            margin-left: 20%;
        }
        .dark .user-message {
            background-color: #2c3e50;
            color: #ecf0f1;
        }
        .bot-message {
            background-color: #e8f5e9;
            color: #2e7d32;
            align-self: flex-start;
            max-width: 80%;
            margin-right: 20%;
        }
        .dark .bot-message {
            background-color: #1b5e20;
            color: #e8f5e9;
        }
        .message pre {
            white-space: pre-wrap;
            word-wrap: break-word;
            margin: 0;
            font-family: inherit;
            line-height: 1.5;
        }
        .message-time {
            font-size: 0.8rem;
            opacity: 0.7;
            text-align: right;
            margin-top: 5px;
        }
        @keyframes fadeIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        /* Fixed chat footer (query bar at bottom) */
        .chat-footer {
            position: fixed;
            bottom: 0;
            left: 0;
            right: 0;
            background: inherit;
            padding: 10px 20px;
            box-shadow: 0 -2px 4px rgba(0,0,0,0.1);
        }
        .chat-footer .chat-form {
            display: flex;
            gap: 10px;
            flex-wrap: wrap;
        }
        .chat-footer .model-select {
            flex: 1;
            max-width: 200px;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
            background-color: white;
        }
        .dark .chat-footer .model-select {
            background-color: #333;
            color: white;
            border-color: #555;
        }
        .chat-footer .prompt-input {
            flex: 3;
            padding: 10px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }
        .dark .chat-footer .prompt-input {
            background-color: #333;
            color: white;
            border-color: #555;
        }
        .chat-footer .submit-btn {
            padding: 10px 20px;
            background-color: var(--primary);
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            transition: background-color 0.3s, transform 0.2s;
        }
        .chat-footer .submit-btn:hover {
            background-color: var(--primary-hover);
            transform: translateY(-1px);
        }
        /* Mobile-specific adjustments */
        @media (max-width: 768px) {
            /* On phone, ensure logout button is same size as clear button */
            .chat-header .actions a.clear-chat,
            .chat-header .actions a.logout {
                padding: 0.5rem 1rem;
                font-size: 1rem;
            }
            /* Right align the actions on mobile */
            .chat-header .actions {
                justify-content: flex-end;
            }
        }
    </style>
</head>
<body class="<?= htmlspecialchars($_SESSION['theme'] ?? 'dark') ?>" id="theme">
    <div class="page-wrapper">
    <div class="chat-container">
        <div class="chat-header">
            <div class="title">
                intelligenc<span style="color: var(--eamp-color);">E&</span> AI
            </div>
            <div class="actions">
                <!-- User box as dropdown -->
                <div class="user-box" title="User"><?= htmlspecialchars($_SESSION['user']) ?>
                    <div class="user-dropdown">
                        <a href="https://t.me/aamershah" target="_blank">Help</a>
                        <a href="#" id="dropdownThemeToggle">Toggle Theme</a>
                    </div>
                </div>
                <a href="?clear_chat=1" class="clear-chat" title="Clear Chat">clear</a>
                <a href="?logout=1" class="logout" title="Logout">
                    <svg viewBox="0 0 24 24">
                        <path fill="#fff" d="M16 13v-2H7V7l-5 5 5 5v-4zM20 3H12v2h8v14h-8v2h8c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2z"/>
                    </svg>
                </a>
            </div>
        </div>
        
        <div class="chat-messages">
            <?php
            $logFile = chat_log_file($_SESSION['user']);
            $fullHistory = file_exists($logFile) ? json_decode(file_get_contents($logFile), true) : [];
            
            $clearFile = "logs/" . preg_replace('/[^A-Za-z0-9_\-]/', '_', $_SESSION['user']) . "_clear.txt";
            if (file_exists($clearFile)) {
                $clearTime = (int)file_get_contents($clearFile);
                $displayHistory = array_filter($fullHistory, function($msg) use ($clearTime) {
                    return $msg['time'] >= $clearTime;
                });
            } else {
                $displayHistory = $fullHistory;
            }
            
            if (!empty($displayHistory)):
                foreach ($displayHistory as $msg):
                    $time = date('Y-m-d H:i:s', $msg['time']);
            ?>
                <div class="message user-message">
                    <strong>You:</strong> <?= htmlspecialchars($msg['you']) ?>
                    <div class="message-time" data-timestamp="<?= $msg['time'] ?>"><?= $time ?></div>
                </div>
                <div class="message bot-message">
                    <strong>intelligenc<span style="color: var(--eamp-color);">E&</span>:</strong>
                    <pre><?= htmlspecialchars($msg['intelligencE&']) ?></pre>
                    <div class="message-time" data-timestamp="<?= $msg['time'] ?>">
                        <?= $time ?> | Model: <?= htmlspecialchars($msg['model'] ?? 'unknown') ?> | 
                        IP: <?= htmlspecialchars($msg['ip'] ?? 'unknown') ?>
                    </div>
                </div>
            <?php
                endforeach;
            else:
            ?>
                <div class="message bot-message">
                    <p>Hello, <?= htmlspecialchars($_SESSION['user']) ?>! How can I assist you today?</p>
                </div>
            <?php endif; ?>
        </div>
    </div>
    
    <!-- Fixed chat footer with query bar -->
    <div class="chat-footer">
        <form method="POST" class="chat-form">
            <select name="model" class="model-select" required>
                <?php
                // Populate dynamic model dropdown using the previously fetched models
                if (!empty($models)) {
                    foreach ($models as $modelData) {
                        // We include only models of type "llm"
                        if ($modelData['type'] === 'llm') {
                            $selected = (isset($_SESSION['model']) && $_SESSION['model'] === $modelData['id']) ? 'selected' : '';
                            echo '<option value="' . htmlspecialchars($modelData['id']) . '" ' . $selected . '>' . htmlspecialchars($modelData['id']) . '</option>';
                        }
                    }
                } else {
                    // Fallback option if fetching models fails
                    echo '<option value="deepseek-coder-33b-instruct">deepseek-coder-33b-instruct</option>';
                }
                ?>
            </select>
            <input type="text" name="prompt" class="prompt-input" placeholder="Type your message here..." required autofocus>
            <button type="submit" class="submit-btn">Send</button>
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
        </form>
    </div>
    </div>
    
    <script>
        // Convert each message-time's data-timestamp attribute to a local string based on the client's browser
        function updateMessageTimes() {
            document.querySelectorAll('.message-time').forEach(function(elem) {
                var ts = elem.getAttribute('data-timestamp');
                if(ts) {
                    var dt = new Date(ts * 1000);
                    elem.innerText = dt.toLocaleString();
                }
            });
        }
        updateMessageTimes();
        
        // Re-use the theme toggle logic on the dropdown link
        document.getElementById('dropdownThemeToggle').addEventListener('click', function(e) {
            e.preventDefault();
            const currentTheme = document.getElementById('theme').className;
            const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
            document.getElementById('theme').className = newTheme;
            
            fetch('', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/x-www-form-urlencoded',
                },
                body: `update_theme=${newTheme}&csrf_token=<?= $_SESSION['csrf_token'] ?>`
            }).then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            }).then(data => {
                console.log('Theme updated:', data.theme);
            }).catch(error => {
                console.error('Error updating theme:', error);
            });
        });
        
        window.onload = function() {
            const chatMessages = document.querySelector('.chat-messages');
            if (chatMessages) {
                chatMessages.scrollTop = chatMessages.scrollHeight;
            }
            const promptInput = document.querySelector('.prompt-input');
            if (promptInput) {
                promptInput.focus();
            }
        };
        
        const chatMessages = document.querySelector('.chat-messages');
        if (chatMessages) {
            const observer = new MutationObserver(function() {
                chatMessages.scrollTop = chatMessages.scrollHeight;
            });
            observer.observe(chatMessages, { childList: true, subtree: true });
        }
    </script>
</body>
</html>
