<?php
    /*
        File: orthros.php
        Description: backend api for orthros (previously bithash), does everything and nothing more. Functions as a pub upload/download reciever and a message que system.
        Copyright 2015 Dylan "Haifisch" Laws
    */
    // I'll improve code comments #son
    include("./lib/AES.class.php");
    include("apns.php");
    error_reporting(E_ERROR | E_WARNING | E_PARSE);

    // initial variables
    $config_array = parse_ini_file("/etc/bithash/config.ini");
    $action = $_GET['action'];
    $UUID = $_GET['UUID'];
    $hashedID = hash("sha256", md5($UUID));
    $globalUserDir = './users/'.$hashedID;
    $globalPubDir = $globalUserDir.'/pub.pub';
    $iv = substr($hashedID, 0, 17) + "9a2ae11d94" + substr($hashedID, 0, -5);
    $aes = new AES($config_array["aes_key"]);
    
    // commonly used functions
    function result($message, $cAction, $errorCode) { // my boy @landaire, you a real one.
        die(json_encode(['result' => $message, 'called' => $cAction, 'error' => $errorCode]));
    }

    function checkFile($fileDir) {
        if (file_exists($fileDir)){
            return true;
        }else{
            return false;
        }
        clearstatcache();
    }

    function delete_files($target) {
        if(is_dir($target)) {
            $files = glob( $target . '*', GLOB_MARK ); //GLOB_MARK adds a slash to directories returned
            foreach($files as $file) {
                delete_files($file);      
            }
            rmdir($target);
        } elseif(is_file($target)) {
            unlink($target);  
        }
    }

    function rand_key($length = 20) {
        $pool = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
        $crypto_rand_secure = function ( $min, $max ) {
            $range = $max - $min;
            if ( $range < 0 ) return $min; // not so random...
            $log    = log( $range, 2 );
            $bytes  = (int) ( $log / 8 ) + 1; // length in bytes
            $bits   = (int) $log + 1; // length in bits
            $filter = (int) ( 1 << $bits ) - 1; // set all lower bits to 1
            do {
                $rnd = hexdec( bin2hex( openssl_random_pseudo_bytes( $bytes ) ) );
                $rnd = $rnd & $filter; // discard irrelevant bits
            } while ( $rnd >= $range );
            return $min + $rnd;
        };

        $token = "";
        $max   = strlen( $pool );
        for ( $i = 0; $i < $length; $i++ ) {
            $token .= $pool[$crypto_rand_secure( 0, $max )];
        }
        return $token;
    }

    if ($action == "version") {
        $orthros_edit_time = filemtime("./orthros.php");
        result("v1.0.0 $orthros_edit_time", "version", 0);
    }

    // initial sanity checks
    if (empty($UUID)) { // check if UUID field is set
        result("UUID is missing!", "init", 1);
    }
    if (!preg_match('/^\{?[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\}?$/', $UUID)) { // check if UUID is valid
        result("UUID is invalid!", "init", 1);
    }
    if (empty($action)) { // get action
        result("action type is missing!", "init", 1);
    }
    if (empty($config_array["aes_key"])) {
        result("aes_key not found in config.ini!", "init", 1);
    }
    if (empty($config_array["server_private_key"])) {
        result("server_private_key location not found in config.ini!", "init", 1);
    }
    if (empty($config_array["server_public_key"])) {
        result("server_public_key location not found in config.ini!", "init", 1);
    }

    // start action checks
    if ($action == "check") {
        if (checkFile($globalPubDir)) {
            result("public key exists", "check", 0);
        } else {
            result("public key does not exist", "check", 1);
        }
    }elseif ($action == "download") {
        if (empty($_GET["receiver"])) {
            result("reciever is missing from request", "download", 1);
        }
        if (!preg_match("/^\{?[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\}?$/", $_GET["receiver"])) {
            result("reciever ID is invalid", "download", 1);
        }
        $receiverPub = './users/'.hash("sha256", md5($_GET["receiver"])).'/pub.pub';
        if (checkFile($receiverPub)) {
            $pub = base64_encode(file_get_contents($receiverPub, true));
            die(json_encode(['pub' => "$pub", 'called' => 'download', 'error' => 0]));
        }else {
            result("public key does not exist for provided UUID", "download", 1);
        }
    }elseif ($action == "upload") {
        // handle the POST data, create folder for UUID, and store the pub in pub.pub
        if (empty($_GET["UUID"])) {
            result("UUID is missing!", "upload", 1);
        }
        if (empty($_POST['pub'])) {
            result("public key is missing from POST!", "upload", 1);
        }
        $unencoded_pub = base64_decode($_POST['pub']);
        if (strlen($unencoded_pub) !== 632) {
            result("submitted pub is invalid in length", "upload", 1);
        }
        if (strpos($unencoded_pub,'<?php') !== false) {
            result("submitted pub is invalid!", "upload", 1);
        }
        if (strpos($unencoded_pub,'-----BEGIN PUBLIC KEY-----') === false) {
            result("submitted pub is missing the RSA header", "upload", 1);
        }
        if (strpos($unencoded_pub,'-----END PUBLIC KEY-----') === false) {
            result("submitted pub is missing the RSA footer", "upload", 1);
        }
        if (!checkFile($globalUserDir.'/queue')) {
            $newDir = $globalUserDir.'/queue';
            mkdir($newDir, 0777, true);
        }
        $newDir = 'users/'.$hashedID;
        mkdir($newDir, 0777, true);
        $pubFile = fopen($globalPubDir, "w") or result("couldn't create public key file on server", "upload", 1);;
        fwrite($pubFile, $unencoded_pub);
        fclose($pubFile);
        result("public key written successfully!", "upload", 0);
    }elseif ($action == "send") {
        // check if UUID was passed
        $orthros_edit_time = filemtime($globalPubDir);
        $totalSeconds = abs($orthros_edit_time-microtime());
        $date = getdate($totalSeconds); 
        $hours = $date['hour'];
        if ($hours > 24) {
            result("Public key is expired! cannot continue request", "send", 1);
        }
        if (empty($_GET["UUID"])) {
            result("UUID is missing", "send", 1);
        }
        if (empty($_GET["receiver"])) {
            result("receiver is missing", "send", 1);
        }
        if (!preg_match("/^\{?[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\}?$/", $_GET["receiver"])) {
            result("reciever ID is invalid", "send", 1);
        }
        if (empty($_POST["msg"])) {
            result("message (msg) is missing from POST", "send", 1);
        }
        if (empty($_POST["key"])) {
            result("one-time key is missing from POST", "send", 1);
        }
        if (!checkFile($globalUserDir."/temp_key")) {
            result("temp_key does not exist!", "send", 1);
        }
        $decrypted_key;
        if (!openssl_private_decrypt(base64_decode(file_get_contents($globalUserDir."/temp_key", true)), $decrypted_key, file_get_contents($config_array["server_private_key"], true))) {
            result("error while decrypting key for server", "send", 1);
        }
        if (strcmp($_POST['key'], $decrypted_key) != 0) {
            result("keys do not match up!", "send", 1);
        }
        // check if requested UUID (user) exists and setup recieving location
        $receiverURL = './users/'.hash("sha256", md5($_GET["receiver"]));
        if (!checkFile($receiverURL)) {
            result("public key does not exist for provided receiving UUID", "send", 1);
        } else {
            if (!checkFile($receiverURL.'queue')) {
                $newDir = $receiverURL.'/queue';
                mkdir($newDir, 0777, true);
            }
        }
        $date = date_create();
        $timestamp = date_timestamp_get($date);
        $raw_msg = $_POST['msg'];
        $aes_msg = $aes->encrypt($raw_msg);
        if (empty($aes_msg)) {
            result("message failed to encrypt with AES", "send", 1);
        }
        $quedMessage = fopen($receiverURL.'/queue/'.$timestamp, "w") or result("couldn't create queue file!", "send", 1);
        fwrite($quedMessage, $aes_msg);
        fclose($quedMessage);

        $apns_config_location = './users/'.hash("sha256", md5($_GET["receiver"])).'/conf';
        if (checkFile($apns_config_location)) {
            $device_token = file_get_contents($apns_config_location, true);
            $device_token = $aes->decrypt($device_token);
            if (!send_push_to($device_token)) {
                result("message successfully written to users queue with notification", "send", 0);
            }
        }
        result("message successfully written to users queue without notification", "send", 0);

    }elseif ($action == "list") {
        $msgs = array_diff(scandir($globalUserDir.'/queue/', 1), array('..', '.', '.DS_Store'));
        if (count($msgs) > 0) {
            die(json_encode(['msgs' => $msgs, 'called' => 'list', 'error' => 0]));
        }else {
            result("no messages found in queue", "list", 1);
        }
    }elseif ($action == "get") {
        if (empty($_GET["msg_id"])) {
            result("msg_id is missing!", "get", 1);
        }
        if (!ctype_digit($_GET["msg_id"])) {
            result("msg_id is invalid!", "get", 1);
        }
        $messageURL = $globalUserDir.'/queue/'.$_GET["msg_id"];
        if (checkFile($messageURL)) {
            $msg = file_get_contents($messageURL, true);
            $msg = $aes->decrypt($msg);
            $msg = json_decode($msg, true);
            die(json_encode(['msg' => $msg, 'called' => 'get', 'error' => 0], JSON_UNESCAPED_SLASHES));
        }else {
            result("message does not exist", "get", 1);
        }
    }elseif ($action == "delete_msg") {
        if (empty($_GET["msg_id"])) {
            result("msg_id is missing!", "delete_msg", 1);
        }
        if (!ctype_digit($_GET["msg_id"])) {
            result("msg_id is invalid!", "delete_msg", 1);
        }
        if (empty($_POST["key"])) {
            result("one-time key is missing!", "delete_msg", 1);
        }
        if (!checkFile($globalUserDir."/temp_key")) {
            result("temp_key does not exist on server!", "delete_msg", 1);
        }
        $decrypted_key;
        if (!openssl_private_decrypt(base64_decode(file_get_contents($globalUserDir."/temp_key", true)), $decrypted_key, file_get_contents($config_array["server_private_key"], true))) {
            result("error while decrypting key!", "delete_msg", 1);
        } else {
            if (strcmp($_POST["key"], $decrypted_key) != 0) {
                result("one-time keys do not match up!", "delete_msg", 1);
            }
            $messageURL = $globalUserDir.'/queue/'.$_GET["msg_id"];
            if (unlink($messageURL)) {
                die(json_encode(['msg' => $_GET["msg_id"], 'called' => 'delete_msg', 'error' => 0]));
            }else {
                result("message does not exist or is already deleted!", "delete_msg", 1);
            }
        }
    }elseif ($action == "gen_key") {
        $receiverPub = $globalPubDir;
        if (checkFile($receiverPub)) {
            $pub = file_get_contents($receiverPub, true);
            $srvr_pub = file_get_contents($config_array["server_public_key"], true);
            // strip, fix, replace.
            $pub = str_replace("-----BEGIN PUBLIC KEY-----", "", $pub);
            $pub = str_replace("-----END PUBLIC KEY-----", "", $pub);
            $pub = str_replace(' ', '+', $pub);
            $pub = "-----BEGIN PUBLIC KEY-----".$pub."-----END PUBLIC KEY-----";
            $key = rand_key();
            $encrypted;
            $copy;
            if (openssl_public_encrypt($key, $encrypted, $pub)) { // encrypt the one-time key with the users pub
                $encrypted = base64_encode($encrypted);
                if (openssl_public_encrypt($key, $copy, $srvr_pub)) { // encrypt again with the servers pub
                    $copy = base64_encode($copy);
                    $tempkey = fopen($globalUserDir.'/temp_key', "w") or result("couldn't create temp_key file!", "gen_key", 1);
                    fwrite($tempkey, $copy);
                    fclose($tempkey);
                } else {
                    result("error while encrypting key for server!", "gen_key", 1);
                }
            } else {
                result("error while encrypting key for user!", "gen_key", 1);
            }
            die(json_encode(['key' => $encrypted, 'called' => 'gen_key', 'error' => 0]));
        }else {
            result("public key does not exist for provided UUID!", "gen_key", 1);
        }
    }elseif ($action == "obliterate") {
        // check if UUID was passed
        if (empty($_GET["UUID"])) {
            result("UUID is missing", "obliterate", 1);
        }
        if (!preg_match("/^\{?[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\}?$/", $_GET["UUID"])) {
            result("reciever ID is invalid", "obliterate", 1);
        }
        if (empty($_POST["key"])) {
            result("one-time key is missing from POST", "obliterate", 1);
        }
        if (!checkFile($globalUserDir."/temp_key")) {
            result("temp_key does not exist!", "obliterate", 1);
        }
        $decrypted_key;
        if (!openssl_private_decrypt(base64_decode(file_get_contents($globalUserDir."/temp_key", true)), $decrypted_key, file_get_contents($config_array["server_private_key"], true))) {
            result("error while decrypting key for server", "obliterate", 1);
        }
        if (strcmp($_POST['key'], $decrypted_key) != 0) {
            result("keys do not match up!", "obliterate", 1);
        }
        $userDirectory = 'users/'.hash("sha256", md5($_GET["UUID"]));
        if (!checkFile($userDirectory)) {
            result("public key does not exist for provided receiving UUID", "obliterate", 1);
        } 
        delete_files($userDirectory);
        result("user was obliterated", "obliterate", 0);
    }elseif ($action == "submit_token") {
        if (empty($_GET["UUID"])) {
            result("UUID is missing", "submit_token", 1);
        }
        if (!preg_match("/^\{?[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\}?$/", $_GET["UUID"])) {
            result("reciever ID is invalid", "submit_token", 1);
        }
        if (empty($_POST["token"])) {
            result("device token is missing", "submit_token", 1);
        }
        $protected_token = $aes->encrypt($_POST["token"]);
        if (empty($protected_token)) {
            result("token failed to encrypt with AES", "submit_devicetoken", 1);
        }
        $apns_config_location = './users/'.hash("sha256",md5($_GET["UUID"])).'/conf';
        $apns_config = fopen($apns_config_location, "w") or result("couldn't create apns config file!", "submit_token", 1);
        fwrite($apns_config, $protected_token);
        fclose($apns_config);
        result("token was successfully submitted", "submit_devicetoken", 0);
    }elseif ($action == "keypair_epoch") {
        $orthros_edit_time = filemtime($globalPubDir);
        result("$orthros_edit_time", "keypair_epoch", 0);
    } elseif ($action == "keypair_replace") {
        // check if UUID was passed
        if (empty($_GET["UUID"])) {
            result("UUID is missing", "keypair_replace", 1);
        }
        if (!preg_match("/^\{?[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\}?$/", $_GET["UUID"])) {
            result("reciever ID is invalid", "keypair_replace", 1);
        }
        if (empty($_POST["key"])) {
            result("one-time key is missing from POST", "keypair_replace", 1);
        }
        if (!checkFile($globalUserDir."/temp_key")) {
            result("temp_key does not exist!", "keypair_replace", 1);
        }
        $decrypted_key;
        if (!openssl_private_decrypt(base64_decode(file_get_contents($globalUserDir."/temp_key", true)), $decrypted_key, file_get_contents($config_array["server_private_key"], true))) {
            result("error while decrypting key for server", "keypair_replace", 1);
        }
        if (strcmp($_POST['key'], $decrypted_key) != 0) {
            result("keys do not match up!", "keypair_replace", 1);
        }
        if (!unlink($globalPubDir)) {
            result("public key does not exist or was already deleted!", "keypair_replace", 1);
        }
        delete_files($globalUserDir.'/queue');
        if (empty($_POST['pub'])) {
            result("public key is missing from POST!", "keypair_replace", 1);
        }
        $unencoded_pub = base64_decode($_POST['pub']);
        if (strlen($unencoded_pub) !== 632) {
            result("submitted pub is invalid in length", "keypair_replace", 1);
        }
        if (strpos($unencoded_pub,'<?php') !== false) {
            result("submitted pub is invalid!", "keypair_replace", 1);
        }
        if (strpos($unencoded_pub,'-----BEGIN PUBLIC KEY-----') === false) {
            result("submitted pub is missing the RSA header", "keypair_replace", 1);
        }
        if (strpos($unencoded_pub,'-----END PUBLIC KEY-----') === false) {
            result("submitted pub is missing the RSA footer", "keypair_replace", 1);
        }
        if (!checkFile($globalUserDir.'/queue')) {
            $newDir = $globalUserDir.'/queue';
            mkdir($newDir, 0777, true);
        }
        $newDir = 'users/'.$hashedID;
        mkdir($newDir, 0777, true);
        $pubFile = fopen($globalPubDir, "w") or result("couldn't create public key file on server", "keypair_replace", 1);;
        fwrite($pubFile, $unencoded_pub);
        fclose($pubFile);
        result("new public key written successfully!", "keypair_replace", 0);
    } else {
        result("$action is not a valid action!", "init", 1);
    }
?>
