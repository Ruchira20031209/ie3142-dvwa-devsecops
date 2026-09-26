<?php

if (isset($_POST['Submit'])) {
    $target = $_POST['ip'] ?? null;

    // Accept one valid IP address, not a command or a list.
    if (!is_string($target) ||
        filter_var($target, FILTER_VALIDATE_IP) === false) {
        $html .= '<pre>Invalid IP address.</pre>';
    } else {
        $process = null;
        $pipes = [];

        try {
            if (!is_executable('/usr/bin/ping')) {
                throw new RuntimeException('Ping executable is unavailable.');
            }

            // Fixed executable and options. No command shell is used.
            $command = [
                '/usr/bin/ping', '-n', '-c', '4',
                '-W', '2', '-w', '8', '--', $target,
            ];

            $descriptors = [
                0 => ['file', '/dev/null', 'r'],
                1 => ['pipe', 'w'],
                2 => ['redirect', 1],
            ];

            $process = proc_open($command, $descriptors, $pipes);

            if (!is_resource($process)) {
                throw new RuntimeException('Unable to start ping.');
            }

            // Keep at most 8 KiB of output.
            $output = stream_get_contents($pipes[1], 8192);

            if ($output === false) {
                throw new RuntimeException('Unable to read ping output.');
            }

            fclose($pipes[1]);
            $exitCode = proc_close($process);
            $process = null;

            if ($output === '') {
                $output = 'Ping finished with exit code ' . $exitCode . '.';
            }

            $safeOutput = htmlspecialchars(
                $output,
                ENT_QUOTES | ENT_SUBSTITUTE,
                'UTF-8'
            );

            $html .= '<pre>' . $safeOutput . '</pre>';
        } catch (Throwable $e) {
            error_log('DVWA ping failed: ' . $e->getMessage());
            $html .= '<pre>Unable to run ping.</pre>';
        } finally {
            foreach ($pipes as $pipe) {
                if (is_resource($pipe)) {
                    fclose($pipe);
                }
            }

            if (is_resource($process)) {
                proc_terminate($process);
                proc_close($process);
            }
        }
    }
}