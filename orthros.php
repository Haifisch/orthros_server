<?php
	/*
		File: orthros.php
		Description: backend api for orthros (previously bithash), does everything and nothing more. Functions as a pub upload/download reciever and a message que system.
		Copyright 2015 Dylan "Haifisch" Laws
	*/
	// I'll improve code comments #son
	error_reporting(E_ERROR | E_WARNING | E_PARSE);
	$config_array = parse_ini_file("config.ini");
	if (empty($_GET['UUID'])) { // check if UUID field is set
		die('{"result":"UUID is missing!", "error":1}');
	}
	if (!preg_match('/^\{?[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\}?$/', $_GET['UUID'])) { // check if UUID is valid
		die('{"result":"UUID is invalid!", "error":1}');
	} 
	if (empty($_GET['action'])) { // get action
		die('{"result":"action type is missing!", "error":1}');
	}
	if (empty($config_array["aes_key"])) {
		die('{"result":"aes_key not found in config.ini!", "error":1}');
	}
	if (empty($config_array["server_private_key"])) {
		die('{"result":"server_private_key location not found in config.ini!", "error":1}');
	}
	$action = $_GET['action'];
	$UUID = $_GET['UUID'];
	$globalUserDir = './users/'.$UUID;
	$globalFileName = $globalUserDir.'/pub.pub';
	$iv = "00f9a6c7e11c245669a2ae11d944c205"; // rnd me pls
	$aes256Key = hash("SHA256", $config_array["aes_key"], true);

	function checkFile($fileDir) {  
		if (file_exists($fileDir)){
			return true;
	    }else{
	    	return false;
	    }
	    clearstatcache();
	}

	function fnEncrypt($sValue, $sSecretKey) {
		global $iv;
	    return rtrim(base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_256, $sSecretKey, $sValue, MCRYPT_MODE_CBC, $iv)), "\0\3");
	}

	function fnDecrypt($sValue, $sSecretKey) {
		global $iv;
	    return rtrim(mcrypt_decrypt(MCRYPT_RIJNDAEL_256, $sSecretKey, base64_decode($sValue), MCRYPT_MODE_CBC, $iv), "\0\3");
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

	if ($action == "check") {
	    if (checkFile($globalFileName)) {
	    	echo '{"result":"public key exsists", "called":"check", "error":0}';
	    } else {
	    	die('{"result":"public key does not exsist", "called":"check", "error":1}');
	    }
	}elseif ($action == "download") {
		if (empty($_GET["receiver"])) {
            die('{"result":"receiver is missing", "called":"download", "error":1}');
        }
        $receiverPub = './users/'.$_GET["receiver"].'/pub.pub';
		if (checkFile($receiverPub)) {
			$pub = file_get_contents($receiverPub, true);
			echo '{"pub":'.json_encode($pub).', "called":"download", "error":0}';
		}else {
			die('{"result":"public key does not exsist for provided UUID", "called":"download", "error":1}');
		}
	}elseif ($action == "upload") {
		// handle the POST data, create folder for UUID, and store the pub in pub.pub
		if (empty($_GET["UUID"])) {
        	die('{"result":"UUID is missing", "called":"send", "error":1}');
        }
		if (empty($_POST['pub'])) {
			die('{"result":"public key is missing!", "called":"upload", "error":1}');
		}
		$newDir = './users/'.$UUID;
		mkdir($newDir, 0777, true);
		$pubFile = fopen($globalFileName, "w") or die('{"result":"couldnt create pub file", "error":1}');
		fwrite($pubFile, $_POST['pub']);
		fclose($pubFile);
	   	echo '{"result":"public key written", "called":"upload", "error":0}';
	}elseif ($action == "send") {
		// check if UUID was passed
		if (empty($_GET["UUID"])) {
        	die('{"result":"UUID is missing", "called":"send", "error":1}');
        }
        if (empty($_GET["receiver"])) {
            die('{"result":"receiver is missing", "called":"send", "error":1}');
        }
		if (empty($_POST["msg"])) {
			die('{"result":"message is missing", "called":"send", "error":1}');
		}
		if (empty($_POST["key"])) {
			die('{"result":"one-time key is missing", "called":"send", "error":1}');
		}
		if (!checkFile($globalUserDir."/temp_key")) {
            die('{"result":"temp_key does not exsist on server", "called":"send", "error":1}');
		}
		$decrypted_key;
		$given_key = $_POST['key'];
		if (!openssl_private_decrypt(base64_decode(file_get_contents($globalUserDir."/temp_key", true)), $decrypted_key, file_get_contents($config_array["server_private_key"], true))) {
        	die ('{"result":"error while decrypting key", "called":"send", "error":1}');
		} 
    	if (strcmp($given_key, $decrypted_key) != 0) {
        	die ('{"result":"keys do not match up","given_key":"'.$_POST["key"].'","decrypted_key":"'.$decrypted_key.'", "called":"send", "error":1}');
    	}
		// check if requested UUID (user) exsists and setup recieving location
		$receiverURL = './users/'.$_GET["receiver"];
		if (!checkFile($receiverURL)) {
        	die('{"result":"public key does not exsist for provided UUID", "called":"send", "error":1}');
        } else {
			if (!checkFile($receiverURL.'queue')) {
        		$newDir = $receiverURL.'/queue';
        		mkdir($newDir, 0777, true);
    		}
		}
		$date = date_create();
		$timestamp = date_timestamp_get($date);
		$quedMessage = fopen($receiverURL.'/queue/'.$timestamp, "w") or die('{"result":"couldnt create queue file", "error":1}');
    	fwrite($quedMessage, fnEncrypt($_POST['msg'],$aes256Key));
    	fclose($quedMessage);
    	echo '{"result":"message written to queue", "called":"send", "error":0}';
	}elseif ($action == "list") {
		$msgs = array_diff(scandir($globalUserDir.'/queue/', 1), array('..', '.', '.DS_Store'));
		if (count($msgs) > 0) {
			echo '{"msgs":'.json_encode($msgs).', "called":"list", "error":0}';
		}else {
			echo '{"result":"no messages in queue", "called":"list", "error":1}';
		}
	}elseif ($action == "get") {
		if (empty($_GET["msg_id"])) {
			die('{"result":"msg_id is missing", "called":"get", "error":1}');
		}
		$messageURL = $globalUserDir.'/queue/'.$_GET["msg_id"];
		if (checkFile($messageURL)) {
			$msg = file_get_contents($messageURL, true);
			$msg = fnDecrypt($msg, $aes256Key);
			echo '{"msg":'.$msg.', "called":"get", "error":0}';
		}else {
			die('{"result":"message does not exsist", "called":"get", "error":1}');
		}
	}elseif ($action == "delete_msg") {
		if (empty($_GET["msg_id"])) {
			die('{"result":"msg_id is missing", "called":"delete_msg", "error":1}');
		}
		if (empty($_POST["key"])) {
			die('{"result":"one-time key is missing", "called":"send", "error":1}');
		}
		if (!checkFile($globalUserDir."/temp_key")) {
            die('{"result":"temp_key does not exsist on server", "called":"send", "error":1}');
		}
		$decrypted_key;
		$given_key = $_POST['key'];
		if (!openssl_private_decrypt(base64_decode(file_get_contents($globalUserDir."/temp_key", true)), $decrypted_key, file_get_contents($config_array["server_private_key"], true))) {
        		die ('{"result":"error while decrypting key", "called":"send", "error":1}');
		} else {
			if (strcmp($_POST["key"], $decrypted_key) != 0) {
	        	die ('{"result":"keys do not match up","given_key":"'.$_POST["key"].'","decrypted_key":"'.$decrypted_key.'", "called":"send", "error":1}');
	    	}
			$messageURL = $globalUserDir.'/queue/'.$_GET["msg_id"];
			if (unlink($messageURL)) {
				echo '{"msg":'.$_GET["msg_id"].', "called":"delete_msg", "error":0}';
			}else {
				die('{"result":"message does not exsist or is already deleted", "called":"delete_msg", "error":1}');
			}
		}
	}elseif ($action == "gen_key") {
        $receiverPub = $globalFileName;
		if (checkFile($receiverPub)) {
			$pub = file_get_contents($receiverPub, true);
			$srvr_pub = file_get_contents($config_array["server_private_key"], true);
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
	    	    		$tempkey = fopen($globalUserDir.'/temp_key', "w") or die('{"result":"couldnt create temp key file", "error":1}');
	        			fwrite($tempkey, $copy);
	        			fclose($tempkey);
	        		} else {
	    	        	die('{"result":"error while encrypting key for server", "called":"gen_key", "error":1}');
	        		}
	     		} else {
	        		die ('{"result":"error while encrypting key for user", "called":"gen_key", "error":1}');
	        	}
			echo '{"key":"'.$encrypted.'", "called":"gen_key", "error":0}';
		}else {
			die('{"result":"public key does not exsist for provided UUID", "called":"gen_key", "error":1}');
		}
	}
?>
