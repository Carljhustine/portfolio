<?php
declare(strict_types=1);


function escape_html(mixed $value): string
{
    return htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}


function make_csrf_token(): string
{
    if (!isset($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return (string) $_SESSION['csrf_token'];
}

function valid_csrf(string $submitted): bool
{
    return isset($_SESSION['csrf_token'])
        && is_string($_SESSION['csrf_token'])
        && hash_equals($_SESSION['csrf_token'], $submitted);
}

function load_account(): ?array
{
    $file = __DIR__ . '/config/credentials.php';
    if (!is_file($file)) {
        return null;
    }
    $account = require $file;
    return is_array($account)
        && isset($account['username'], $account['password_hash'])
        ? $account
        : null;
}

if (PHP_SAPI === 'cli' && ($argv[1] ?? '') === 'setup-admin') {
    $file = __DIR__ . '/config/credentials.php';
    if (is_file($file)) {
        fwrite(STDERR, "An account already exists. Delete config/credentials.php locally to replace it.\n");
        exit(1);
    }

    fwrite(STDOUT, 'Admin username (3–64 letters, numbers, dots, underscores, or hyphens): ');
    $username = trim((string) fgets(STDIN));
    if (preg_match('/^[a-zA-Z0-9._-]{3,64}$/', $username) !== 1) {
        fwrite(STDERR, "That username is not valid.\n");
        exit(1);
    }

    fwrite(STDOUT, 'Admin password (at least 12 characters): ');
    $password = rtrim((string) fgets(STDIN), "\r\n");
    if (strlen($password) < 12) {
        fwrite(STDERR, "Choose a password with at least 12 characters.\n");
        exit(1);
    }

    $hash = password_hash($password, PASSWORD_DEFAULT);
    if ($hash === false) {
        fwrite(STDERR, "Could not create a password hash.\n");
        exit(1);
    }
    $contents = "<?php\ndeclare(strict_types=1);\nreturn "
        . var_export(['username' => $username, 'password_hash' => $hash], true)
        . ";\n";
    if (file_put_contents($file, $contents, LOCK_EX) === false) {
        fwrite(STDERR, "Could not write config/credentials.php.\n");
        exit(1);
    }
    @chmod($file, 0600);
    fwrite(STDOUT, "Account created. Keep config/credentials.php private.\n");
    exit(0);
}

$portfolio = [
    'name' => 'Carl Jhustine S. Pepanio',
    'title' => 'IT Student',
    'about' => 'Hello, I am Carl Jhustine S. Pepanio. I am 19 years old and currently enrolled at Pamantasan ng Lungsod ng Valenzuela, where I am studying for a Bachelor of Science in Information Technology. I live in Veinte Reales, Valenzuela City.',
    'interests' => ['Chess', 'Jigsaw Puzzles', 'Badminton', 'Video Games',],
    'email' => ['cj.pepanio@gmail.com', 'cj.pepanio1326@gmail.com'],
    'phone' => '09561556057',
    'location' => 'Valenzuela City, Philippines',
    'projects' => [
        [
            'title' => 'LCC school management system',
            'description' => 'Describe a project you have built and what it does.',
            'technologies' => ['Python', 'HTML', 'CSS' , 'JavaScript'],
        ],
        [
            'title' => 'WPT - Warehouse Performance Tracker',
            'description' => 'A system to track and analyze warehouse performance metrics.',
            'technologies' => ['PHP', 'HTML'],
        ],
    ],
    'skills' => [
        'Programming Languages' => ['Java', 'Python', 'C#'],
        'Web Development' => ['HTML', 'CSS', 'JavaScript', 'PHP'],
        'Database Management' => ['MySQL'],
        'Development Tools' => ['Visual Studio Code', 'PyCharm', 'NetBeans', 'Notepad++', 'Git'],

        'Other Technical Skills' => ['PC troubleshooting', 'PC Building',],
    ],
];

$emailAddresses = array_values(array_filter(
    (array) $portfolio['email'],
    static fn ($email) => is_string($email) && trim($email) !== ''
));
$isHttps = !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => $isHttps,
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

$pages = ['home', 'about', 'projects', 'skills', 'contact'];
$page = (string) ($_GET['page'] ?? 'home');
if (!in_array($page, $pages, true)) {
    $page = 'home';
}
$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = (string) ($_POST['action'] ?? '');

    if ($action === 'login') {
        $account = load_account();
        $username = trim((string) ($_POST['username'] ?? ''));
        $password = (string) ($_POST['password'] ?? '');

        if (!valid_csrf((string) ($_POST['csrf_token'] ?? ''))) {
            $errors[] = 'Your form expired. Reload the page and try again.';
        } elseif ($account !== null
            && hash_equals((string) $account['username'], $username)
            && password_verify($password, (string) $account['password_hash'])) {
            session_regenerate_id(true);
            $_SESSION = [
                'authenticated' => true,
                'csrf_token' => bin2hex(random_bytes(32)),
            ];
            header('Location: index.php');
            exit;
        } else {
            $errors[] = 'The username or password is incorrect.';
        }
    } elseif ($action === 'logout') {
        if (!valid_csrf((string) ($_POST['csrf_token'] ?? ''))) {
            http_response_code(400);
            exit('Invalid logout request. Return to the portfolio and try again.');
        }
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $cookie = session_get_cookie_params();
            setcookie(session_name(), '', [
                'expires' => time() - 42000,
                'path' => $cookie['path'],
                'domain' => $cookie['domain'],
                'secure' => $cookie['secure'],
                'httponly' => $cookie['httponly'],
                'samesite' => 'Lax',
            ]);
        }
        session_destroy();
        header('Location: index.php');
        exit;
    }
}

if (($_SESSION['authenticated'] ?? false) !== true) {
    $errorText = implode(' ', $errors);
    ?>
    <!doctype html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>Login · <?= escape_html($portfolio['name']) ?></title>
        <link rel="stylesheet" href="assets/css/style.css?v=<?= filemtime(__DIR__ . '/assets/css/style.css') ?>">
        <script src="assets/js/script.js" defer></script>
    </head>
    <body>
    <main id="main-content" class="login-wrap">
        <section class="login-card" aria-labelledby="login-title">
            <h1 id="login-title">Welcome back</h1>
            <p class="muted">Sign in to view the portfolio.</p>
            <?php if ($errorText !== ''): ?>
                <div class="message error" role="alert">
                    <?= escape_html($errorText) ?>
                </div>
            <?php endif; ?>
            <form method="post" action="index.php" class="form-stack">
                <input type="hidden" name="action" value="login">
                <input type="hidden" name="csrf_token" value="<?= escape_html(make_csrf_token()) ?>">
                <label for="username">Username</label>
                <input id="username" name="username" autocomplete="username" required maxlength="64">
                <label for="password">Password</label>
                <div class="password-field">
                    <input id="password" name="password" type="password" autocomplete="current-password" required>
                    <button
                        type="button"
                        class="text-button"
                        data-password-toggle="password"
                        aria-pressed="false"
                    >
                        Show
                    </button>
                </div>
                <button class="button button-primary full-width" type="submit">Sign in</button>
            </form>
        </section>
    </main>
    </body>
    </html>
    <?php
    exit;
}

$pageTitles = [
    'home' => 'Home',
    'about' => 'About',
    'projects' => 'Projects',
    'skills' => 'Skills',
    'contact' => 'Contact',
];
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="theme-color" content="#f6f7fb">
    <title><?= escape_html($pageTitles[$page]) ?> · <?= escape_html($portfolio['name']) ?></title>
    <link rel="stylesheet" href="assets/css/style.css?v=<?= filemtime(__DIR__ . '/assets/css/style.css') ?>">
    <script src="assets/js/script.js" defer></script>
</head>
<body>
<a class="skip-link" href="#main-content">Skip to content</a>

<header class="site-header">
    <a class="brand" href="index.php">
        <?= escape_html($portfolio['name']) ?><span class="brand-dot">.</span>
    </a>

    <button
        class="menu-toggle"
        type="button"
        aria-expanded="false"
        aria-controls="primary-nav"
    >
        Menu
    </button>

    <nav id="primary-nav" class="nav-links" aria-label="Main navigation">
        <?php foreach ($pageTitles as $key => $label): ?>
            <a
                href="index.php?page=<?= escape_html($key) ?>"
                <?= $page === $key ? 'aria-current="page"' : '' ?>
            >
                <?= escape_html($label) ?>
            </a>
        <?php endforeach; ?>

        <form method="post" action="index.php" class="logout-form" onsubmit="return confirm('Are you sure you want to log out?');">
            <input type="hidden" name="action" value="logout">
            <input
                type="hidden"
                name="csrf_token"
                value="<?= escape_html(make_csrf_token()) ?>"
            >
            <button type="submit" class="nav-logout">Log out</button>
        </form>
    </nav>
</header>

<main id="main-content">
    <?php if ($errors): ?>
        <div class="message error" role="alert">
            <ul>
                <?php foreach ($errors as $error): ?>
                    <li><?= escape_html($error) ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>


    <?php if ($page === 'home'): ?>
        <section class="hero section-shell">
            <div class="hero-copy">
                <p class="eyebrow">Hello, I’m</p>
                <h1><?= escape_html($portfolio['name']) ?></h1>
                <p class="hero-title"><?= escape_html($portfolio['title']) ?></p>

                <div class="button-row">
                    <a class="button button-primary" href="index.php?page=projects">
                        View my projects
                    </a>
                    <a class="button button-secondary" href="index.php?page=contact">
                        Contact me
                    </a>
                </div>
            </div>

            <div class="portrait-wrap profile-photo-wrap">
                <img class="profile-photo"
                    src="assets/images/profile.jpg"
                    alt="Profile photo"
                >
            </div>
        </section>

        <section class="section-shell section-intro">
            <p class="eyebrow">A little about me</p>
            <p><?= escape_html($portfolio['about']) ?></p>
            <a class="inline-link" href="index.php?page=about">
                More about me →
            </a>
        </section>

    <?php elseif ($page === 'about'): ?>
        <section class="section-shell page-heading">
            <p class="eyebrow">About</p>
            <h1>A bit about me</h1>
        </section>

        <section class="section-shell two-column">
            <div class="portrait-wrap about-portrait profile-photo-wrap">
                <img class="profile-photo"
                    src="assets/images/profile.jpg"
                    alt="Profile photo"
                >
            </div>

            <div>
                <p><?= escape_html($portfolio['about']) ?></p>
                <h3>Interests</h3>
                <ul class="tag-list">
                    <?php foreach ($portfolio['interests'] as $interest): ?>
                        <li><?= escape_html($interest) ?></li>
                    <?php endforeach; ?>
                </ul>
            </div>
        </section>

    <?php elseif ($page === 'projects'): ?>
        <section class="section-shell page-heading">
            <p class="eyebrow">Selected work</p>
            <h1>Projects</h1>
            <p class="lead">
                Replace the sample entries in the project list near the top of index.php.
            </p>
        </section>

        <section class="section-shell card-grid">
            <?php foreach ($portfolio['projects'] as $project): ?>
                <article class="project-card is-visible">

                    <div class="project-body">
                        <p class="eyebrow">Project</p>
                        <h2><?= escape_html($project['title']) ?></h2>
                        <p><?= escape_html($project['description']) ?></p>

                        <ul class="tag-list">
                            <?php foreach ($project['technologies'] as $technology): ?>
                                <li><?= escape_html($technology) ?></li>
                            <?php endforeach; ?>
                        </ul>

                    </div>
                </article>
            <?php endforeach; ?>
        </section>

    <?php elseif ($page === 'skills'): ?>
        <section class="section-shell page-heading">
            <p class="eyebrow">What I work with</p>
            <h1>Skills</h1>
            <p class="lead">
                Edit the skill lists near the top of index.php. No proficiency scores are assumed.
            </p>
        </section>

        <section class="section-shell skills-grid">
            <?php foreach ($portfolio['skills'] as $category => $items): ?>
                <article class="skill-card">
                    <div class="skill-icon" aria-hidden="true">✳</div>
                    <h2><?= escape_html($category) ?></h2>
                    <ul>
                        <?php foreach ($items as $item): ?>
                            <li><?= escape_html($item) ?></li>
                        <?php endforeach; ?>
                    </ul>
                </article>
            <?php endforeach; ?>
        </section>

    <?php elseif ($page === 'contact'): ?>
        <section class="section-shell page-heading">
            <p class="eyebrow">Get in touch</p>
            <h1>Contact information</h1>
            <p class="lead">Use the contact details below to get in touch.</p>
        </section>

        <section class="section-shell contact-layout">
            <div class="contact-details">
                <h2>Contact details</h2>

                <?php if ($emailAddresses): ?>
                    <p>
                        <span class="detail-label">Email</span>
                        <?php foreach ($emailAddresses as $index => $email): ?>
                            <?php if ($index > 0): ?><br><?php endif; ?>
                            <a href="mailto:<?= escape_html($email) ?>">
                                <?= escape_html($email) ?>
                            </a>
                        <?php endforeach; ?>
                    </p>
                <?php endif; ?>

                <?php if ($portfolio['phone'] !== ''): ?>
                    <p>
                        <span class="detail-label">Phone</span>
                        <?= escape_html($portfolio['phone']) ?>
                    </p>
                <?php endif; ?>

                <?php if ($portfolio['location'] !== ''): ?>
                    <p>
                        <span class="detail-label">Location</span>
                        <?= escape_html($portfolio['location']) ?>
                    </p>
                <?php endif; ?>



            </div>

        </section>
    <?php endif; ?>
</main>

</body>
</html>
