<?php

require_once "base.php";

$ucid = "njg44"; // <-- set your ucid

// Don't edit the arrays below, they are used to test your code
$array1 = ["hello world!", "php programming", "special@#$%^&characters", "numbers 123 456", "mIxEd CaSe InPut!"];
$array2 = ["hello world", "php programming", "this is a title case test", "capitalize every word", "mixEd CASE input"];
$array3 = ["  hello   world  ", "php    programming  ", "  extra    spaces  between   words   ",
    "      leading and trailing spaces      ", "multiple      spaces"];
$array4 = ["hello world", "php programming", "short", "a", "even"];


function transformText($arr, $arrayNumber) {
    // Only make edits between the designated "Start" and "End" comments
    printArrayInfoBasic($arr, $arrayNumber);

    // Challenge 1: Remove non-alphanumeric characters except spaces
    // Challenge 2: Convert text to Title Case
    // Challenge 3: Trim leading/trailing spaces and remove duplicate spaces
    // Result 1-3: Assign final phrase to `$placeholderForModifiedPhrase`
    // Challenge 4 (extra credit): Extract up to the middle 3 characters (middle index and +/- 1 if it's not the first/last character),
    // Do not include the first or last character of the phrase/word. (e.g., oven should show as ve)
    // assign the result to `$placeholderForMiddleCharacters`
    // If the phrase is shorter than 3 characters, return "Not enough characters"

    // Step 1: sketch out plan using comments (include ucid and date)
    //Remove non-alphanumeric characters (except spaces) — using regex.
    //Convert to title case — lowercase the string then ucwords() it.
    //Trim spaces and collapse multiple spaces to a single space — trim() and preg_replace().
    //njg44 6/16/25

    // Step 2: Add/commit your outline of comments (required for full credit)
    // Step 3: Add code to solve the problem (add/commit as needed)
    $placeholderForModifiedPhrase = "";
    $placeholderForMiddleCharacters = "";
    foreach ($arr as $index => $text) {
        // Start Solution Edits

        // Step 1: Remove non-alphanumeric characters except spaces
        $cleaned = preg_replace("/[^a-zA-Z0-9 ]/", "", $text);

        // Step 2: Convert to title case
        $titleCase = ucwords(strtolower($cleaned));

        // Step 3: Trim and collapse extra spaces
        $singleSpaced = preg_replace("/\s+/", " ", trim($titleCase));

        // Final result
        $placeholderForModifiedPhrase = $singleSpaced;

        // End Solution Edits
        //njg44 6/16/25
        echo "<div>";
        printStringTransformations($index, $placeholderForModifiedPhrase, $placeholderForMiddleCharacters);
        echo "</div>";
    }

    echo "<br>______________________________________<br>";
}

// Run the problem
printHeader($ucid, 4);
transformText($array1, 1);
transformText($array2, 2);
transformText($array3, 3);
transformText($array4, 4);
printFooter($ucid, 4);

?>