<?php

// Only these application-owned pages may be included.
$baseDirectory = dirname(__DIR__);

$allowedPages = [
    'include.php' => $baseDirectory . '/include.php',
    'file1.php'   => $baseDirectory . '/file1.php',
    'file2.php'   => $baseDirectory . '/file2.php',
    'file3.php'   => $baseDirectory . '/file3.php',
];

// Opening the page without a selection shows the normal menu.
$requestedPage = $_GET['page'] ?? 'include.php';

if (!is_string($requestedPage) ||
    !array_key_exists($requestedPage, $allowedPages)) {
    http_response_code(400);

    $page['body'] .= '<div class="body_padded">'
        . '<h1>Vulnerability: File Inclusion</h1>'
        . '<div class="vulnerable_code_area">'
        . '<pre>Invalid page selection.</pre>'
        . '</div>'
        . '<p><a href="?page=include.php">Back to File Inclusion</a></p>'
        . '</div>';

    dvwaHtmlEcho($page);
    exit;
}

// The include path comes entirely from our fixed server-side mapping.
$file = $allowedPages[$requestedPage];