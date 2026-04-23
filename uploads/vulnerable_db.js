const mysql = require('mysql');

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'password',
    database: 'test_db'
});

// الثغرة: استخدام ${userId} مباشرة جوه الاستعلام
const getUserProfile = (userId) => {
    const sqlQuery = `SELECT * FROM profiles WHERE id = ${userId}`;

    connection.query(sqlQuery, (error, results) => {
        if (error) throw error;
        console.log(results);
    });
};

// لو اليوزر بعت userId قيمته "1; DROP TABLE profiles;"
getUserProfile("1; DROP TABLE profiles;");