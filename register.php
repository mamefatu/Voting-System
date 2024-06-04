<?php
global $conn;
session_start();
require_once 'db_connect.php';

// Génération du jeton CSRF
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

// Traitement du formulaire
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Vérification du jeton CSRF
    if (!hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        die('Jeton CSRF invalide');
    }

    // Récupération et validation des données du formulaire
    $name = htmlspecialchars(trim($_POST['name']));
    $email = filter_var($_POST['email'], FILTER_SANITIZE_EMAIL);
    $username = isset($_POST['username']) ? htmlspecialchars(trim($_POST['username'])) : null;
    $cin = isset($_POST['cin']) ? htmlspecialchars(trim($_POST['cin'])) : null;
    $password = trim($_POST['password']);

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        die('Format d\'email invalide');
    }

    if (strlen($password) < 8) {
        die('Le mot de passe doit comporter au moins 8 caractères');
    }

    // Hachage du mot de passe
    $passwordHash = password_hash($password, PASSWORD_BCRYPT);

    // Préparation et exécution de la requête SQL
    $stmt = $conn->prepare('INSERT INTO users (name, email, username, cin, password) VALUES (?, ?, ?, ?, ?)');
    $stmt->bind_param('sssss', $name, $email, $username, $cin, $passwordHash);

    if ($stmt->execute()) {
        echo 'Inscription réussie. Vous pouvez maintenant vous connecter.';
    } else {
        echo 'Erreur: ' . $stmt->error;
    }

    $stmt->close();
    $conn->close();
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta content="width=device-width, initial-scale=1.0" name="viewport">
    <title>Register | Taanal</title>
    <?php include('./header.php'); ?>
    <style>
        body {
            width: 100%;
            height: calc(100%);
            background: #007bff;
        }
        main#main {
            width: 100%;
            height: calc(100%);
            background: white;
        }
        #register-right {
            position: absolute;
            right: 0;
            width: 40%;
            height: calc(100%);
            background: white;
            display: flex;
            align-items: center;
        }
        #register-left {
            position: absolute;
            left: 0;
            width: 60%;
            height: calc(100%);
            background: #00000061;
            display: flex;
            align-items: center;
        }
        #register-right .card {
            margin: auto;
        }
        .logo {
            margin: auto;
            font-size: 8rem;
            background: white;
            padding: .5em 0.8em;
            border-radius: 50% 50%;
            color: #000000b3;
        }
    </style>
</head>
<body>
<main id="main" class="alert-info">
    <div id="register-left">
        <div class="logo">
            <i class="fa fa-poll-h"></i>
        </div>
    </div>
    <div id="register-right">
        <div class="card col-md-8">
            <div class="card-body">
                <form id="register-form" method="POST" action="register.php">
                    <div class="form-group">
                        <label for="name" class="control-label">Name</label>
                        <input type="text" id="name" name="name" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label for="email" class="control-label">Email</label>
                        <input type="email" id="email" name="email" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label for="username" class="control-label">Username</label>
                        <input type="text" id="username" name="username" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label for="cin" class="control-label">N CIN:</label>
                        <input type="text" id="cin" name="cin" class="form-control" required>
                    </div>
                    <div class="form-group">
                        <label for="password" class="control-label">Password</label>
                        <input type="password" id="password" name="password" class="form-control" required>
                    </div>
                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                    <center><button class="btn-sm btn-block btn-wave col-md-4 btn-primary">Register</button></center>
                </form>
            </div>
        </div>
    </div>
</main>
</body>
</html>
