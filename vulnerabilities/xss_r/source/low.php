<?php

header('X-XSS-Protection: 0');

if (array_key_exists('name', $_GET)) {
    $name = $_GET['name'];

    if (!is_string($name)) {
        $html .= '<pre>Invalid name.</pre>';
    } elseif ($name !== '') {
        // Encode input before placing it into HTML text.
        $safeName = htmlspecialchars(
            $name,
            ENT_QUOTES | ENT_SUBSTITUTE,
            'UTF-8'
        );

        $html .= '<pre>Hello ' . $safeName . '</pre>';
    }
}