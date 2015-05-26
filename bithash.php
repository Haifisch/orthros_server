<?php
	/*
		File: bithash.php
		Description: backend api for orthros (previously bithash), does everything and nothing more. Functions as a pub upload/download reciever and a message que system.
		Written by: Haifisch
	*/
	// Stupid simple.
	error_reporting(E_ERROR | E_WARNING | E_PARSE);
	if (empty($_GET['UUID'])) { // check if UUID field is set
		die('{"result":"UUID is missing!", "error":1}');
	}
	if (!preg_match('/^\{?[A-Za-z0-9]{8}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{4}-[A-Za-z0-9]{12}\}?$/', $_GET['UUID'])) { // check if UUID is valid
		die('{"result":"UUID is invalid!", "error":1}');
	} 
	if (empty($_GET['action'])) { // get action
		die('{"result":"action type is missing!", "error":1}');
	}
	$action = $_GET['action'];
	$UUID = $_GET['UUID'];
	$globalUserDir = './users/'.$UUID;
	$globalFileName = $globalUserDir.'/pub.pub';
	
	function checkFile($fileDir) {  
		if (file_exists($fileDir)){
			return true;
	    }else{
	    	return false;
	    }
	    clearstatcache();
	}

	function rand_key( $type = 'alnum', $length = 20 ) {
		switch ( $type ) {
			case 'alnum':
				$pool = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
				break;
			case 'alpha':
				$pool = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ';
				break;
			case 'hexdec':
				$pool = '0123456789abcdef';
				break;
			case 'numeric':
				$pool = '0123456789';
				break;
			case 'nozero':
				$pool = '123456789';
				break;
			case 'distinct':
				$pool = '2345679ACDEFHJKLMNPRSTUVWXYZ';
				break;
			default:
				$pool = (string) $type;
				break;
		}
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
		if (empty($_GET["key"])) {
			die('{"result":"one-time key is missing", "called":"send", "error":1}');
		}
		if (!checkFile("./users/".$UUID."/temp_key")) {
            		die('{"result":"temp_key does not exsist on server", "called":"send", "error":1}');
		}
		$decrypted_key;
		if (!openssl_private_decrypt(base64_decode(file_get_contents("./users/".$UUID."/temp_key", true)), $decrypted_key, file_get_contents("/etc/bithash/private_key.pem", true))) {
        		die ('{"result":"error while decrypting key", "called":"send", "error":1}');
		} 
    	if (!strcmp($_POST["key"], $decrypted_key)) {
        	die ('{"result":"keys do not match up", "called":"send", "error":1}');
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
    	fwrite($quedMessage, $_POST['msg']);
    	fclose($quedMessage);
    	echo '{"result":"message written to queue", "called":"send", "error":0}';
	}elseif ($action == "list") {
		$msgs = array_diff(scandir($globalUserDir.'/queue/', 1), array('..', '.'));
		if (count($msgs) > 0) {
			echo '{"msgs":'.json_encode($msgs).', "called":"list", "error":0}';
		}else {
			echo '{"result":"no messages in queue", "called":"list", "error":1}';
		}
	}elseif ($action == "get") {
		if (empty($_GET["msg_id"])) {
			die('{"result":"message_id is missing", "called":"get", "error":1}');
		}
		$messageURL = $globalUserDir.'/queue/'.$_GET["msg_id"];
		if (checkFile($messageURL)) {
			$msg = file_get_contents($messageURL, true);
			echo '{"msg":'.$msg.', "called":"get", "error":0}';
		}else {
			die('{"result":"message does not exsist", "called":"get", "error":1}');
		}
	}elseif ($action == "delete_msg") {
		if (empty($_GET["msg_id"])) {
			die('{"result":"message_id is missing", "called":"get", "error":1}');
		}
		$messageURL = $globalUserDir.'/queue/'.$_GET["msg_id"];
		if (unlink($messageURL)) {
			echo '{"msg":'.$_GET["msg_id"].', "called":"delete_msg", "error":0}';
		}else {
			die('{"result":"message does not exsist or is already deleted", "called":"delete_msg", "error":1}');
		}
	}elseif ($action == "gen_key") {
        $receiverPub = './users/'.$UUID.'/pub.pub';
		if (checkFile($receiverPub)) {
			$pub = file_get_contents($receiverPub, true);
			$srvr_pub = file_get_contents("/etc/bithash/public_key.pem", true);
			// strip, replace, glue. aka, whatisphp. 
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
        	    			$tempkey_loc = './users/'.$UUID;
	    	    			$tempkey = fopen($tempkey_loc.'/temp_key', "w") or die('{"result":"couldnt create temp key file", "error":1}');
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
