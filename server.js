const express = require('express');
const bodyParser = require('body-parser');
const multer = require('multer');
const sqlite3 = require('sqlite3').verbose();
const fs = require('fs');
const path = require('path');
const helmet = require('helmet');

const app = express();
const upload = multer();

app.use(helmet());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public', {
    maxAge: '1d',
    etag: false
}));

const db = new sqlite3.Database('./submissions.db');

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS submissions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        phone TEXT NOT NULL,
        organization TEXT NOT NULL,
        carPlate TEXT NOT NULL,
        signature TEXT NOT NULL,
        submitted_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        organization TEXT NOT NULL
    )`);
});

// Middleware for authentication
function authenticate(req, res, next) {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).send('未授权');
    }

    const token = authHeader.split(' ')[1];
    const [username, password] = Buffer.from(token, 'base64').toString().split(':');
    db.get(`SELECT * FROM users WHERE username = ? AND password = ?`, [username, password], (err, user) => {
        if (err || !user) {
            return res.status(401).send('未授权');
        }
        req.user = user;
        next();
    });
}

// Submission routes
app.post('/submit', upload.none(), (req, res) => {
    const { name, phone, organization, carPlate, signature } = req.body;

    if (!name || !phone || !organization || !carPlate || !signature) {
        return res.status(400).send('所有字段都是必填的');
    }

    const phonePattern = /^\d{11}$/;
    const carPlatePattern = /^[\u4e00-\u9fa5]{1}[A-Z]{1}[\dA-Z]{5}$/;

    if (!phonePattern.test(phone)) {
        return res.status(400).send('电话格式不正确');
    }

    if (!carPlatePattern.test(carPlate)) {
        return res.status(400).send('车牌号格式不正确');
    }

    db.run(`INSERT INTO submissions (name, phone, organization, carPlate, signature) VALUES (?, ?, ?, ?, ?)`,
        [name, phone, organization, carPlate, signature], function (err) {
            if (err) {
                return res.status(500).send('提交失败');
            }
            res.status(200).send('提交成功');
        });
});

app.get('/submissions', authenticate, (req, res) => {
    let query = `SELECT * FROM submissions WHERE organization = ?`;
    const params = [req.user.organization];

    if (req.query.date) {
        query += ` AND date(submitted_at) = date(?)`;
        params.push(req.query.date);
    }

    db.all(query, params, (err, rows) => {
        if (err) {
            return res.status(500).send('无法获取数据');
        }
        res.json(rows);
    });
});

app.delete('/submissions/:id', authenticate, (req, res) => {
    db.run(`DELETE FROM submissions WHERE id = ? AND organization = ?`, [req.params.id, req.user.organization], function (err) {
        if (err || this.changes === 0) {
            return res.status(500).send('删除失败');
        }
        res.status(200).send('删除成功');
    });
});

app.get('/download', authenticate, (req, res) => {
    db.all(`SELECT * FROM submissions WHERE organization = ?`, [req.user.organization], (err, rows) => {
        if (err) {
            return res.status(500).send('无法下载数据');
        }

        let csv = 'ID,姓名,电话,单位,包车牌号,手写签名,提交时间\n';
        rows.forEach(row => {
            csv += `${row.id},${row.name},${row.phone},${row.organization},${row.carPlate},${row.signature},${row.submitted_at}\n`;
        });

        res.header('Content-Type', 'text/csv');
        res.attachment('submissions.csv');
        res.send(csv);
    });
});

// User management routes
app.post('/users', authenticate, (req, res) => {
    if (req.user.organization !== '总管理员') {
        return res.status(403).send('没有权限');
    }
    const { username, password, organization } = req.body;
    db.run(`INSERT INTO users (username, password, organization) VALUES (?, ?, ?)`, [username, password, organization], function (err) {
        if (err) {
            return res.status(500).send('创建用户失败');
        }
        res.status(201).send('创建用户成功');
    });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});