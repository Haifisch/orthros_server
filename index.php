<?php
	/*
		File: index.php
		Copyright 2015 Dylan "Haifisch" Laws
	*/
	// I'll improve code comments #son
	error_reporting(E_ERROR | E_WARNING | E_PARSE);

	if ($_GET['action'] || $_GET['UUID']) {
		require('orthros.php');
	} else {
		header('Location: apidocs.html');
	}
?>
