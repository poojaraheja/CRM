<?php
require "config.php";

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;
use PHPMailer\PHPMailer\Exception;



function connect()
{
    $mysqli = new mysqli(SERVER, USERNAME, PASSWORD, DATABASE);

    if ($mysqli->connect_errno != 0) {


        return false;

    } else {

        return $mysqli;

    }
}





function registerUser($email, $username, $password, $confirm_password)
{

    $mysqli = connect();

    if ($mysqli == false) {
        return "connection failed";
    }

    $args = func_get_args();

    $args = array_map(function ($value) {

        return trim($value);

    }, $args);

    foreach ($args as $value) {

        if (empty($value)) {

            return "All Fields are required";

        }

    }

    foreach ($args as $value) {

        if (preg_match("/([<|>])/", $value)) {

            return "<> Characters are not allowed";

        }

    }

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {

        return "Email is not valid";

    }

    $sql = "SELECT email FROM admin where email = ?";

    $stmt = $mysqli->prepare($sql);

    $stmt->bind_param('s', $email);

    $stmt->execute();

    $result = $stmt->get_result();

    $data = $result->fetch_assoc();

    if ($data != NULL) {

        return "Email already exists Please use different email";

    }

    if (strlen($username) > 50) {

        return "Username is too long";

    }

    $stmt = $mysqli->prepare("SELECT username FROM admin WHERE username = ?");

    $stmt->bind_param("s", $username);

    $stmt->execute();

    $result = $stmt->get_result();

    $data = $result->fetch_assoc();

    if ($data != null) {
        return "Username already exists.";
    }

    if (strlen($password) > 50) {

        return "Password is too long";

    }

    if ($password != $confirm_password) {

        return "Passwords do not match";

    }

    $hashed_password = password_hash($password, PASSWORD_DEFAULT);

    $stmt = $mysqli->prepare("INSERT INTO admin(username, password, email) VALUES(?,?,?)");

    $stmt->bind_param("sss", $username, $hashed_password, $email);

    $stmt->execute();

    if ($stmt->affected_rows != 1) {

        return "An error occurred,Please try again";

    } else {

        return "success";

    }

}






function login($username, $password)
{

    $mysqli = connect();

    $username = trim($username);

    $password = trim($password);

    if ($username == "" || $password == "") {

        return "Both fields are required";

    }

    $username = filter_var($username, FILTER_SANITIZE_STRING);
    $password = filter_var($password, FILTER_SANITIZE_STRING);

    $sql = "SELECT username, password FROM admin WHERE username=?";

    $stmt = $mysqli->prepare($sql);

    $stmt->bind_param("s", $username);

    $stmt->execute();

    $result = $stmt->get_result();

    $data = $result->fetch_assoc();

    if ($data == null) {

        return "wrong username or password";

    }

    if (
        password_verify($password, $data['password']) == false
    ) {

        return "Wrong username or password";

    } else {

        $_SESSION['user'] = $username;

        header("location:index.html");

    }

}






function logout()
{

    session_destroy();

    header("location:login.php");

    exit();

}

function sendMail($email, $verification_code)
{

    require('PHPMailer/PHPMailer.php');
    require('PHPMailer/SMTP.php');
    require('PHPMailer/Exception.php');

    $mail = new PHPMailer(true);

    try {
        $mail->isSMTP(); //Send using SMTP
        $mail->Host = 'smtp.gmail.com'; //Set the SMTP server to send through
        $mail->SMTPAuth = true; //Enable SMTP authentication
        $mail->Username = 'loginpage219@gmail.com'; //SMTP username
        $mail->Password = 'pchrphgbbmsgjrfa'; //SMTP password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_SMTPS; //Enable implicit TLS encryption
        $mail->Port = 465; //TCP port to connect to; use 587 if you have set `SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS`

        //Recipients
        $mail->setFrom('loginpage219@gmail.com', 'CS Cloud');
        $mail->addAddress($email);

        //Content
        $mail->isHTML(true); //Set email format to HTML
        $mail->Subject = 'Password Recovery';
        $mail->Body = '
      <h7>You can log in with your new password</h7>
      <br><p>New Password: ' . $verification_code . '</p>';

        $mail->send();
        return true;
    } catch (Exception $e) {
        return false;
    }
}



function pass_reset($email)
{



    $mysqli = connect();

    $email = trim($email);

    if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {

        return "Email is not valid";

    }

    $stmt = $mysqli->prepare("SELECT email FROM admin WHERE email=?");

    $stmt->bind_param('s', $email);

    $stmt->execute();

    $result = $stmt->get_result();

    $data = $result->fetch_assoc();

    if ($data == NULL) {

        return "Email does not exist in the database";

    }

    $str = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    $password_length = 7;

    $shuffled_str = str_shuffle($str);

    $new_pass = substr($shuffled_str, 0, $password_length);


    // $subject = "Password Recovery";

    // $body = "You can log in with your new password" . "\r\n";

    // $body .= $new_pass;

    // $headers = "MIME-Version: 1.0" . "\r\n";

    // $headers .= "Content-type:text/html;charset=UTF-8" . "\r\n";

    // $headers .= "From: rahejapooja670@gmail.com" . "\r\n";


    $send = sendMail($email, $new_pass);

    if ($send == false) {

        return "Email not send, please try again";

    } else {

        $hashed_password = password_hash($new_pass, PASSWORD_DEFAULT);

        $stmt = $mysqli->prepare("UPDATE admin SET password = ? WHERE email = ?");

        $stmt->bind_param("ss", $hashed_password, $email);

        $stmt->execute();

        if ($stmt->affected_rows != 1) {

            return "There was a connection error, Please try again.";

        } else {

            return "success";

        }

    }

}





function deleteAccount()
{



}

?>