<?php


require(__DIR__ . "/R6_insert.php");

// Add back $db param when cache function created
function fetch_act_data($actname, $kills, $deaths, $matches)
{
    $db = getDB();

    $endpoint = "https://rainbow-six.p.rapidapi.com/general/pc/VG-Rahkwal";
    $isRapidAPI = true;
    $rapidAPIHost = "x-rapidapi-host: rainbow-six.p.rapidapi.com";

    $result = get($endpoint, "R6_API_KEY", $data, $isRapidAPI, $rapidAPIHost);

    if ($result["status"] === 200 && isset($result["response"])) {
        $decoded = json_decode($result["response"], true);

        foreach ($decoded as $acccount => $r6) {
            error_log("== Parsed Account Data ==");

            $actname = $r6["name"] ?? '';
            $kills = $r6["kills"] ?? '';
            $deaths = $r6["deaths"] ?? '';
            $matches = $r6["matches"] ?? '';
            $is_api = 1;

            error_log("name: $actname");
            error_log("kills: $kills");
            error_log("deaths: $deaths");
            error_log("matches: $matches");

            $activityFlags = [];


            error_log("is_api: $is_api");

            // Insert using the passed DB handle
            insert_account($db, array_merge([
                "name" => $actname,
                "kills" => $kills,
                "deaths" => $deaths,
                "matches" => $matches,
                "is_api" => $is_api, ], $activityFlags));
        }

        return $decoded;
    }

    return [];
}