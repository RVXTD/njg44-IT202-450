<?php

/**
 * This file is a wrapper for our API calls.
 * Here, each endpoint needed will be exposes as a function.
 * The function will take the parameters needed for the API call and return the result.
 * The function will also handle the API key and endpoint.
 * Requires the api_helper.php file and load_api_keys.php file.
 */

/**
 * Fetches the stock quote for a given symbol.
 */
function fetch_quote($symbol)
{
     $data = ["platform" => $_GET["platform"], "username" => $_GET["username"]];
    $endpoint = "https://rainbow-six.p.rapidapi.com/general";
    $isRapidAPI = true;
    $rapidAPIHost =  "rainbow-six.p.rapidapi.com";
    $result = get($endpoint, "R6_API_KEY", $data, $isRapidAPI, $rapidAPIHost);
    
    error_log("API Response: " . var_export($result, true));
    if (se($result, "status", 400, false) == 200 && isset($result["response"])) {
        $result = json_decode($result["response"], true);
    } else {
        $result = [];
    }
    $transformedResult = [];
    // transform data to match our DB structure
    if (isset($result["Global Quote"])) {
        
        $quote = $result["Global Quote"];
        foreach ($quote as $k => $v) {
            // remove the numbers from the keys and fix spaces to underscores
            // "01. symbol"
            //["01.", "symbol"]
            $k = str_replace(" ", "_", /*symbol*/ explode(" ", $k, 2)[1]);

            $v = str_replace("%", "", $v);
            if (is_numeric($v)) {
                if(strpos($v, ".") !== false) {
                    $v = floatval($v);
                } else {
                    $v = intval($v);
                }
            }
            // assign updated/mapped key/values
            $transformedResult[$k] = $v;
        }
        // removed used data
        unset($transformedResult["previous_close"]);
        unset($transformedResult["change"]);
    }
    return $transformedResult;
}