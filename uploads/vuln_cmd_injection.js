const { exec } = require('child_process');

function runSystemCommand(userInput) {
    // Danger: Passing user input directly to OS shell
    exec('ping ' + userInput, (error, stdout, stderr) => {
        if (error) console.error(error);
        console.log(stdout);
    });
}