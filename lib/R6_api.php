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
    //example of cached data to save the quotas, don't forget to comment out the get() if using the cached data for testing
    /* $result = ["status" => 200, "response" => '{
        "Global Quote": {
            "01. symbol": "MSFT",
            "02. open": "420.1100",
            "03. high": "422.3800",
            "04. low": "417.8400",
            "05. price": "421.4400",
            "06. volume": "17861855",
            "07. latest trading day": "2024-04-02",
            "08. previous close": "424.5700",
            "09. change": "-3.1300",
            "10. change percent": "-0.7372%"
        }
    }'];*/
    error_log("API Response: " . var_export($result, true));
    if (se($result, "status", 400, false) == 200 && isset($result["response"])) {
        $result = json_decode($result["response"], true);
    } else {
        $result = [];
    }
    $transformedResult = [];
    // transform data to match our DB structure
   
        unset($transformedResult["previous_close"]);
        unset($transformedResult["change"]);
    }
    return $transformedResult;
}
function search_companies($search){
    $data = ["function" => "SYMBOL_SEARCH", "keywords" => $search, "datatype" => "json"];
    $endpoint = "https://alpha-vantage.p.rapidapi.com/query";
    $isRapidAPI = true;
    $rapidAPIHost = "alpha-vantage.p.rapidapi.com";
    $result = get($endpoint, "STOCK_API_KEY", $data, $isRapidAPI, $rapidAPIHost);
    
    error_log("API Response: " . var_export($result, true));
    if (se($result, "status", 400, false) == 200 && isset($result["response"])) {
        $result = json_decode($result["response"], true);
    } else {
        $result = [];
    }
    // transform data
    if(isset($result["bestMatches"])){
        $result = $result["bestMatches"];
        $transformedResult = [];
        foreach($result as $r){
            
            // fixed keys
            foreach($r as $k=>$v){
                // "1. symbol"
                // ["1.", "symbol"]
                // "symbol"
                $nk = str_replace(" ", "_", explode(" ", $k, 2)[1]);
                $r[$nk] = $v;
                unset($r[$k]);
            }
            if(strlen($r["symbol"]) > 6){
                continue;
            }
            // map/extract desired information
            $data = [
                "symbol"=>$r["symbol"],
                "name" =>$r["name"],
                "type"=>$r["type"],
                "region"=>$r["region"],
                "currency"=>$r["currency"],
                "is_api"=>1
            ];
            array_push($transformedResult, $data);
        }
    }
    return $transformedResult;
}