<?php
require 'vendor/autoload.php'; // Ensure PHPMailer is installed via Composer

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $smtpHost = $_POST['smtp_host'];
    $smtpPort = $_POST['smtp_port'];
    $smtpUser = $_POST['smtp_user'];
    $smtpPass = $_POST['smtp_pass'];
    $testEmail = $_POST['test_email']; // New field

    $result = [];
    try {
        $mail = new PHPMailer(true);
        $mail->isSMTP();
        $mail->Host = $smtpHost;
        $mail->Port = $smtpPort;
        $mail->SMTPAuth = true;
        $mail->Username = $smtpUser;
        $mail->Password = $smtpPass;

        // Use a browser proxy if needed
        if (!empty($_POST['proxy'])) {
            $proxy = $_POST['proxy'];
            $mail->SMTPOptions = [
                'ssl' => [
                    'verify_peer' => false,
                    'verify_peer_name' => false,
                    'allow_self_signed' => true,
                    'proxy' => $proxy,
                ],
            ];
        }

        $mail->setFrom($smtpUser);
        $mail->addAddress($testEmail); // Send to specified test email
        $mail->Subject = 'SMTP Test';
        $mail->Body = 'This is a test email sent from SMTP Checker at ' . date('Y-m-d H:i:s');

        $mail->send();
        $result['status'] = 'Success';
    } catch (Exception $e) {
        $result['status'] = 'Failed';
        $result['error'] = $mail->ErrorInfo;
    }

    // Get IP and country
    $ip = gethostbyname($smtpHost);
    $geoInfo = file_get_contents("http://ip-api.com/json/$ip");
    $geoData = json_decode($geoInfo, true);

    $result['ip'] = $ip;
    $result['country'] = $geoData['country'] ?? 'Unknown';

    echo json_encode($result);
    exit;
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SMTP Checker</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <style>
        .console {
            background: #1e1e1e;
            color: #fff;
            padding: 15px;
            border-radius: 5px;
            margin-top: 20px;
            min-height: 150px;
            font-family: monospace;
        }
        .success { color: #00ff00; }
        .error { color: #ff0000; }
    </style>
</head>
<body class="container py-4">
    <h1 class="mb-4">SMTP Checker</h1>
    <div class="row">
        <div class="col-md-6">
            <form method="POST" id="smtpForm" class="card p-4">
                <div class="mb-3">
                    <label for="smtp_host" class="form-label">SMTP Host:</label>
                    <input type="text" class="form-control" id="smtp_host" name="smtp_host" required>
                </div>

                <div class="mb-3">
                    <label for="smtp_port" class="form-label">SMTP Port:</label>
                    <input type="number" class="form-control" id="smtp_port" name="smtp_port" required>
                </div>

                <div class="mb-3">
                    <label for="smtp_user" class="form-label">SMTP Username:</label>
                    <input type="text" class="form-control" id="smtp_user" name="smtp_user" required>
                </div>

                <div class="mb-3">
                    <label for="smtp_pass" class="form-label">SMTP Password:</label>
                    <input type="password" class="form-control" id="smtp_pass" name="smtp_pass" required>
                </div>

                <div class="mb-3">
                    <label for="test_email" class="form-label">Test Email Address:</label>
                    <input type="email" class="form-control" id="test_email" name="test_email" required>
                </div>

                <div class="mb-3">
                    <label for="proxy" class="form-label">Proxy (optional):</label>
                    <input type="text" class="form-control" id="proxy" name="proxy">
                </div>

                <button type="submit" class="btn btn-primary">Check SMTP</button>
            </form>
        </div>
        <div class="col-md-6">
            <div class="console" id="console">
                > SMTP Checker ready...
            </div>
        </div>
    </div>

    <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
    <script>
        $(document).ready(function() {
            $('#smtpForm').on('submit', function(e) {
                e.preventDefault();
                const console = $('#console');
                console.append('\n> Testing SMTP connection...');
                
                $.ajax({
                    url: '',
                    method: 'POST',
                    data: $(this).serialize(),
                    success: function(response) {
                        const result = JSON.parse(response);
                        if (result.status === 'Success') {
                            console.append(`\n<span class="success">> Email sent successfully!</span>`);
                            console.append(`\n> Server IP: ${result.ip}`);
                            console.append(`\n> Country: ${result.country}`);
                        } else {
                            console.append(`\n<span class="error">> Failed: ${result.error}</span>`);
                        }
                    },
                    error: function() {
                        console.append('\n<span class="error">> Server error occurred</span>');
                    }
                });
            });
        });
    </script>
</body>
</html>
