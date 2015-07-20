<?php
	$config_array = parse_ini_file("/etc/bithash/config.ini");
	$apns_passphrase = $config_array["apns_pass"];
	function send_push_to($device)
    {
        set_time_limit(0);
        $passphrase = $apns_passphrase;
        $message = "You have a new message!";
        $deviceIds = $device;
     
        // this is where you can customize your notification
        $payload = '{"aps":{"alert":"' . $message . '","sound":"default","badge":1}}';
         
        $result = 'Start' . '\n';
     
        $ctx = stream_context_create();
        stream_context_set_option($ctx, 'ssl', 'local_cert', '/etc/bithash/orthros_apns_cert.pem');
        stream_context_set_option($ctx, 'ssl', 'passphrase', $passphrase);

        sleep(1);
         
        $fp = stream_socket_client('ssl://gateway.sandbox.push.apple.com:2195', $err, $errstr, 60, STREAM_CLIENT_CONNECT | STREAM_CLIENT_PERSISTENT, $ctx);
        if (!$fp) {
            result("Failed to connect to Apple's push server", "push_notification", 1);
        } 
     
        $msg = chr(0) . pack('n', 32) . pack('H*', $device) . pack('n', strlen($payload)) . $payload;
         
        $result = fwrite($fp, $msg, strlen($msg));
         
        if (!$result) {
            return 1;
        } else {
            return 0;
        }
     
        if ($fp) {
            fclose($fp);
        }
        set_time_limit(30);
    }
?>