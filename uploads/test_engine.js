var express = require('express');
var app = express();

app.get('/', function(req, res) {
    var user_input = req.query.input;

    // دي الجريمة اللي ESLint هيمسكها فوراً (Detect Eval)
    // Rule: security/detect-eval-with-expression
    eval(user_input);
});