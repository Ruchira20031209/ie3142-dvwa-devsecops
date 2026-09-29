<?php

if (isset($_REQUEST['Submit'])) {
    // Accept a single positive integer within the database integer range.
    $input = $_REQUEST['id'] ?? null;

    $id = is_string($input)
        ? filter_var($input, FILTER_VALIDATE_INT, [
            'options' => [
                'min_range' => 1,
                'max_range' => 2147483647,
            ],
        ])
        : false;

    if ($id === false) {
        $html .= '<pre>Invalid user ID. Enter a positive whole number.</pre>';
    } else {
        try {
            $rows = [];

            switch ($_DVWA['SQLI_DB']) {
                case MYSQL:
                    mysqli_report(MYSQLI_REPORT_ERROR | MYSQLI_REPORT_STRICT);

                    $db = $GLOBALS['___mysqli_ston'];

                    // Keep the SQL statement separate from the supplied ID.
                    $stmt = $db->prepare(
                        'SELECT first_name, last_name FROM users WHERE user_id = ?'
                    );

                    $stmt->bind_param('i', $id);
                    $stmt->execute();
                    $stmt->bind_result($firstName, $lastName);

                    while ($stmt->fetch()) {
                        $rows[] = [
                            'first_name' => $firstName,
                            'last_name' => $lastName,
                        ];
                    }

                    $stmt->close();
                    break;

                case SQLITE:
                    global $sqlite_db_connection;

                    $sqlite_db_connection->enableExceptions(true);

                    $stmt = $sqlite_db_connection->prepare(
                        'SELECT first_name, last_name FROM users WHERE user_id = :id'
                    );

                    $stmt->bindValue(':id', $id, SQLITE3_INTEGER);
                    $result = $stmt->execute();

                    while ($row = $result->fetchArray(SQLITE3_ASSOC)) {
                        $rows[] = $row;
                    }

                    $result->finalize();
                    $stmt->close();
                    break;

                default:
                    throw new RuntimeException('Unsupported database backend.');
            }

            if ($rows === []) {
                $html .= '<pre>User not found.</pre>';
            }

            foreach ($rows as $row) {
                // Encode database values before inserting them into HTML.
                $first = htmlspecialchars(
                    (string) $row['first_name'],
                    ENT_QUOTES | ENT_SUBSTITUTE,
                    'UTF-8'
                );

                $last = htmlspecialchars(
                    (string) $row['last_name'],
                    ENT_QUOTES | ENT_SUBSTITUTE,
                    'UTF-8'
                );

                $html .= "<pre>ID: {$id}<br />First name: {$first}<br />Surname: {$last}</pre>";
            }
        } catch (Throwable $e) {
            // Record technical details in server logs.
            error_log('DVWA SQLi lookup failed: ' . $e->getMessage());

            // Show a generic message to the browser.
            $html .= '<pre>Unable to retrieve user details.</pre>';
        }
    }
}