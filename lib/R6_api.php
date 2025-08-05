<?php

$curl = curl_init();

curl_setopt_array($curl, [
	CURLOPT_URL => "https://rainbow-six.p.rapidapi.com/general/pc/VG-Rahkwal",
	CURLOPT_RETURNTRANSFER => true,
	CURLOPT_ENCODING => "",
	CURLOPT_MAXREDIRS => 10,
	CURLOPT_TIMEOUT => 30,
	CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
	CURLOPT_CUSTOMREQUEST => "GET",
	CURLOPT_HTTPHEADER => [
		"x-rapidapi-host: rainbow-six.p.rapidapi.com",
		"x-rapidapi-key: 55c3c19516mshccf881b1c1f1334p1f3dbajsn548aaa99584b"
	],
]);

$response = curl_exec($curl);
$err = curl_error($curl);

curl_close($curl);

if ($err) {
	echo "cURL Error #:" . $err;
} else {
	echo $response;
}