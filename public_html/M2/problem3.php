<?php

require_once "base.php";

$ucid = "mt85"; // <-- set your ucid

// Don't edit the arrays below, they are used to test your code
$array1 = [42, -17, 89, -256, 1024, -4096, 50000, -123456];
$array2 = [3.14159265358979, -2.718281828459, 1.61803398875, -0.5772156649, 0.0000001, -1000000.0];
$array3 = [1.1, -2.2, 3.3, -4.4, 5.5, -6.6, 7.7, -8.8];
$array4 = ["123", "-456", "789.01", "-234.56", "0.00001", "-99999999"];
$array5 = [-1, 1, 2.0, -2.0, "3", "-3.0"];

function bePositive($arr, $arrayNumber)
{
    // Only make edits between the designated "Start" and "End" comments
    printArrayInfoMixed($arr, $arrayNumber);

    // Challenge 1: Make each value positive
    // Challenge 2: Convert the values back to their original data type and assign it to the proper slot of the `output` array
    // Step 1: sketch out plan using comments (include ucid and date)

    //Loop through the array.
    //Detect the type of each item.
    //Convert it to a float or int for numeric operation.
    //Take the absolute value.
    //Convert the number back to its original type:
    //if original was int → cast to int
    //if float → float
    //if string → string
    //Store the converted value in the same index in the $output array.
    //njg44 6/16/25

    // Step 2: Add/commit your outline of comments (required for full credit)
    // Step 3: Add code to solve the problem (add/commit as needed)

    $output = array_fill(0, count($arr), null); // Initialize output array
    // Start Solution Edits
foreach ($arr as $i => $val) {
        $originalType = gettype($val);
        $absVal = abs($val); // abs() works with int, float, and numeric strings

        switch ($originalType) {
            case "integer":
                $output[$i] = (int)$absVal;
                break;
            case "double":
                $output[$i] = (float)$absVal;
                break;
            case "string":
                $output[$i] = (string)$absVal;
                break;
            default:
                // fallback for unexpected types
                $output[$i] = $absVal;
                break;
        }
    }
    //njg44 6/16/25
    // End Solution Edits
    echo "<span>Output: </span>";
    printOutputWithType($output);
    echo "<br>______________________________________<br>";
}

// Run the problem
printHeader($ucid, 3);
bePositive($array1, 1);
bePositive($array2, 2);
bePositive($array3, 3);
bePositive($array4, 4);
bePositive($array5, 5);
printFooter($ucid, 3);