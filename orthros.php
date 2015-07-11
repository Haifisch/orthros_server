<?php
	/*
		File: orthros.php
		Description: backend api for orthros (previously bithash), does everything and nothing more. Functions as a pub upload/download reciever and a message que system.
		Copyright 2015 Dylan "Haifisch" Laws
	*/
	// I'll improve code comments #son
	include("./lib/AES.class.php");

	// initial variables
	$config_array = parse_ini_file("/etc/bithash/config.ini");
	$action = $_GET['action'];
	$UUID = $_GET['UUID'];
	$hashedID = md5($_GET['UUID']);
	$globalUserDir = './users/'.$hashedID;
	$globalFileName = $globalUserDir.'/pub.pub';
	//$iv = substr($hashedID, 0, 17) + "9a2ae11d94" + substr($hashedID, 0, -5); // rnd me pls
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

	function deleteDir($target) {
	    exec('rm -rf '.$target); // this /can't/ be safe...
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

	// initial sanity checks
	if (empty($UUID)) { // check if UUID field is set
		result("UUID is missing!", "init", 1);
	}
	if (!preg_match('/^\{?[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\}?$/', $_GET['UUID'])) { // check if UUID is valid
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
	    if (checkFile($globalFileName)) {
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
        $receiverPub = './users/'.md5($_GET["receiver"]).'/pub.pub';
		if (checkFile($receiverPub)) {
			$pub = file_get_contents($receiverPub, true);
			die(json_encode(['pub' => $pub, 'called' => 'download', 'error' => 0]));
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
		if (strlen($_POST['pub']) !== 274) {
			result("submitted pub is invalid in length", "upload", 1);
		}
		if (strpos($_POST['pub'],'<?php') !== false) {
			result("submitted pub is invalid!", "upload", 1);
		}
		if (strpos($_POST['pub'],'-----BEGIN PUBLIC KEY-----') === false) {
			result("submitted pub is missing the RSA header", "upload", 1);
		}
		if (strpos($_POST['pub'],'-----END PUBLIC KEY-----') === false) {
			result("submitted pub is missing the RSA footer", "upload", 1);
		}
		$newDir = 'users/'.$hashedID;
		mkdir($newDir, 0777, true);
		$pubFile = fopen($globalFileName, "w") or result("couldn't create public key file on server", "upload", 1);;
		fwrite($pubFile, $_POST['pub']);
		fclose($pubFile);
		result("public key written successfully!", "upload", 0);
	}elseif ($action == "send") {
		// check if UUID was passed
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
		$given_key = $_POST['key'];
		if (!openssl_private_decrypt(base64_decode(file_get_contents($globalUserDir."/temp_key", true)), $decrypted_key, file_get_contents($config_array["server_private_key"], true))) {
        	result("error while decrypting key for server", "send", 1);
		}
    	if (strcmp($given_key, $decrypted_key) != 0) {
    		result("keys do not match up!", "send", 1);
    	}
		// check if requested UUID (user) exists and setup recieving location
		$receiverURL = './users/'.md5($_GET["receiver"]);
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
    	result("message successfully written to users queue", "send", 0);
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
		$given_key = $_POST['key'];
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
        $receiverPub = $globalFileName;
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
		$given_key = $_POST['key'];
		if (!openssl_private_decrypt(base64_decode(file_get_contents($globalUserDir."/temp_key", true)), $decrypted_key, file_get_contents($config_array["server_private_key"], true))) {
        	result("error while decrypting key for server", "obliterate", 1);
		}
    	if (strcmp($given_key, $decrypted_key) != 0) {
    		result("keys do not match up!", "obliterate", 1);
    	}
		$userDirectory = 'users/'.md5($_GET["UUID"]);
		if (!checkFile($userDirectory)) {
			result("public key does not exist for provided receiving UUID $userDirectory", "obliterate", 1);
        } 
        deleteDir($userDirectory);
    	result("user was obliterated $userDirectory", "obliterate", 0);
	}
?>
