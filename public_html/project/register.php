<?php
require(__DIR__ . "/../../partials/nav.php");
reset_session(); // Ensures fresh session at register
?>
<h3>Register</h3>
<form onsubmit="return validate(this)" method="POST">
    <div>
        <label for="email">Email</label>
        <input id="email" type="email" name="email" required value="<?= se($_POST, "email", "") ?>" />
    </div>
    <div>
        <label for="username">Username</label>
        <input type="text" name="username" required maxlength="30" value="<?= se($_POST, "username", "") ?>" />
    </div>
    <div>
        <label for="pw">Password</label>
        <input type="password" id="pw" name="password" required minlength="8" />
    </div>
    <div>
        <label for="confirm">Confirm</label>
        <input type="password" name="confirm" required minlength="8" />
    </div>
    <input type="submit" value="Register" />
</form>

<script>
function validate(form) {
    const email = form.email.value.trim();
    const username = form.username.value.trim();
    const password = form.password.value;
    const confirm = form.confirm.value;

    if (!email || !username || !password || !confirm) {
        alert("All fields are required.");
        return false;
    }

    if (!email.match(/^[^@]+@[^@]+\.[^@]+$/)) {
        alert("Please enter a valid email address.");
        return false;
    }

    if (password.length < 8) {
        alert("Password must be at least 8 characters.");
        return false;
    }

    if (password !== confirm) {
        alert("Passwords do not match.");
        return false;
    }

    return true;
}
</script>

<?php
if (isset($_POST["email"], $_POST["password"], $_POST["confirm"], $_POST["username"])) {
    $email = se($_POST, "email", "", false);
    $password = se($_POST, "password", "", false);
    $confirm = se($_POST, "confirm", "", false);
    $username = se($_POST, "username", "", false);

    $hasError = false;

    // Sanitize + Validate
    $email = sanitize_email($email);
    if (!is_valid_email($email)) {
        flash("Invalid email address.", "danger");
        $hasError = true;
    }

    if (!is_valid_username($username)) {
        flash("Username must be lowercase, alphanumerical, and can only contain _ or -", "danger");
        $hasError = true;
    }

    if (!is_valid_password($password)) {
        flash("Password must be at least 8 characters long.", "danger");
        $hasError = true;
    }

    if (!is_valid_confirm($password, $confirm)) {
        flash("Passwords must match.", "danger");
        $hasError = true;
    }

    if (!$hasError) {
        $hashed_password = password_hash($password, PASSWORD_BCRYPT);
        $db = getDB();

        $stmt = $db->prepare("INSERT INTO Users (email, password, username) VALUES (:email, :password, :username)");
        try {
            $stmt->execute([
                ":email" => $email,
                ":password" => $hashed_password,
                ":username" => $username
            ]);
            flash("Successfully registered! You can now log in.", "success");
            // Redirect to login or clear form (optional)
        } catch (PDOException $e) {
            users_check_duplicate($e); // Handles unique constraints
        } catch (Exception $e) {
            flash("There was an error registering. Please try again.", "danger");
            error_log("Registration Error: " . var_export($e, true));
        }
    }
}
require(__DIR__ . "/../../partials/flash.php");
?>
