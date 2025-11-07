// =====================================================
// خادم نظام الفصول الدراسية الذكي - محسن لـ Vercel
// Classroom Management System - Vercel Optimized Server
// =====================================================

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const compression = require('compression');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const sqlite3 = require('sqlite3').verbose();
const { Pool } = require('pg');
const path = require('path');

const app = express();

// إعدادات أمان متقدمة
app.use(helmet({
    crossOriginEmbedderPolicy: false,
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'", "https:"],
            fontSrc: ["'self'", "https:"],
            objectSrc: ["'none'"],
            mediaSrc: ["'self'"],
            frameSrc: ["'none'"],
        }
    }
}));

// ضغط البيانات
app.use(compression());

// معالجة CORS
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ['*'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With']
}));

// تحديد معدل الطلبات
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 دقيقة
    max: 100, // حد أقصى 100 طلب لكل IP
    message: {
        error: 'تم تجاوز حد الطلبات المسموح. يرجى المحاولة لاحقاً.',
        retryAfter: '15 minutes'
    }
});
app.use('/api/', limiter);

// معالجة JSON وURL-encoded
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// مسار الثابت للملفات العامة
app.use(express.static('public', {
    maxAge: '1y',
    etag: true,
    lastModified: true
}));

// الصفحة الرئيسية
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// صفحات النظام
app.get('/admin', (req, res) => {
    res.sendFile(path.join(__dirname, 'templates', 'admin_enhanced.html'));
});

app.get('/teacher', (req, res) => {
    res.sendFile(path.join(__dirname, 'templates', 'teacher.html'));
});

app.get('/parent', (req, res) => {
    res.sendFile(path.join(__dirname, 'templates', 'parent.html'));
});

app.get('/supervisor', (req, res) => {
    res.sendFile(path.join(__dirname, 'templates', 'supervisor.html'));
});

// إعداد قاعدة البيانات - دعم متعدد
let db;
const isVercel = process.env.DATABASE_URL || process.env.POSTGRES_URL;

if (isVercel) {
    // استخدام PostgreSQL على Vercel
    console.log('🔄 استخدام PostgreSQL - Vercel');
    db = new Pool({
        connectionString: process.env.DATABASE_URL || process.env.POSTGRES_URL,
        ssl: {
            rejectUnauthorized: false
        }
    });
} else {
    // استخدام SQLite محلياً
    console.log('🔄 استخدام SQLite - محلي');
    db = new sqlite3.Database('classroom_system.db');
}

// =====================================================
// وظائف قاعدة البيانات المساعدة
// =====================================================

async function query(sql, params = []) {
    return new Promise((resolve, reject) => {
        if (isVercel) {
            db.query(sql, params)
                .then(result => resolve(result))
                .catch(reject);
        } else {
            db.all(sql, params, (err, rows) => {
                if (err) reject(err);
                else resolve(rows);
            });
        }
    });
}

async function run(sql, params = []) {
    return new Promise((resolve, reject) => {
        if (isVercel) {
            db.query(sql, params)
                .then(result => resolve(result))
                .catch(reject);
        } else {
            db.run(sql, params, function(err) {
                if (err) reject(err);
                else resolve({ changes: this.changes, lastID: this.lastID });
            });
        }
    });
}

// =====================================================
// إنشاء الجداول عند الحاجة
// =====================================================

async function initializeDatabase() {
    try {
        // جدول المستخدمين
        await run(`CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            name TEXT NOT NULL,
            email TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // جدول الطلاب
        await run(`CREATE TABLE IF NOT EXISTS students (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT,
            parent_name TEXT,
            parent_phone TEXT,
            class TEXT,
            grade TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // جدول الحضور
        await run(`CREATE TABLE IF NOT EXISTS attendance (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            student_id TEXT NOT NULL,
            date TEXT NOT NULL,
            status TEXT NOT NULL,
            teacher_id INTEGER,
            notes TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // جدول المعلمين
        await run(`CREATE TABLE IF NOT EXISTS teachers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            teacher_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            email TEXT,
            phone TEXT,
            subject TEXT,
            class_assigned TEXT,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // جدول الفصول
        await run(`CREATE TABLE IF NOT EXISTS classes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            class_name TEXT NOT NULL,
            grade TEXT NOT NULL,
            teacher_id INTEGER,
            student_count INTEGER DEFAULT 0,
            created_at DATETIME DEFAULT CURRENT_TIMESTAMP
        )`);

        // إضافة مستخدم افتراضي إذا لم يكن موجوداً
        const adminExists = await query('SELECT COUNT(*) as count FROM users WHERE role = "admin"');
        const count = adminExists[0]?.count || 0;
        
        if (count === 0) {
            const hashedPassword = await bcrypt.hash('admin123', 10);
            await run('INSERT INTO users (username, password, role, name) VALUES (?, ?, ?, ?)', 
                ['admin', hashedPassword, 'admin', 'مدير النظام']);
            console.log('✅ تم إنشاء المستخدم الافتراضي: admin / admin123');
        }

        console.log('✅ تم تهيئة قاعدة البيانات بنجاح');
    } catch (error) {
        console.error('❌ خطأ في تهيئة قاعدة البيانات:', error);
    }
}

// =====================================================
// APIs الأساسية
// =====================================================

// Health Check
app.get('/api/health', async (req, res) => {
    try {
        const dbStatus = isVercel ? 'PostgreSQL' : 'SQLite';
        
        // اختبار اتصال قاعدة البيانات
        await query('SELECT 1');
        
        res.json({
            status: 'healthy',
            database: dbStatus,
            version: '2.0.0-VERCEL',
            timestamp: new Date().toISOString(),
            environment: process.env.NODE_ENV || 'development',
            uptime: process.uptime()
        });
    } catch (error) {
        res.status(503).json({
            status: 'unhealthy',
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// المصادقة
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        
        if (!username || !password) {
            return res.status(400).json({ error: 'اسم المستخدم وكلمة المرور مطلوبان' });
        }

        const users = await query('SELECT * FROM users WHERE username = ?', [username]);
        
        if (users.length === 0) {
            return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
        }

        const user = users[0];
        const isValidPassword = await bcrypt.compare(password, user.password);
        
        if (!isValidPassword) {
            return res.status(401).json({ error: 'اسم المستخدم أو كلمة المرور غير صحيحة' });
        }

        const token = jwt.sign(
            { 
                id: user.id, 
                username: user.username, 
                role: user.role,
                name: user.name 
            },
            process.env.JWT_SECRET || 'classroom_secret_2024',
            { expiresIn: '24h' }
        );

        res.json({
            success: true,
            token,
            user: {
                id: user.id,
                username: user.username,
                role: user.role,
                name: user.name
            }
        });
    } catch (error) {
        console.error('خطأ في تسجيل الدخول:', error);
        res.status(500).json({ error: 'خطأ في الخادم' });
    }
});

// إدارة الطلاب
app.get('/api/students', async (req, res) => {
    try {
        const students = await query('SELECT * FROM students ORDER BY created_at DESC');
        res.json({ success: true, data: students });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/students', async (req, res) => {
    try {
        const { student_id, name, email, parent_name, parent_phone, class: className, grade } = req.body;
        
        const result = await run(
            'INSERT INTO students (student_id, name, email, parent_name, parent_phone, class, grade) VALUES (?, ?, ?, ?, ?, ?, ?)',
            [student_id, name, email, parent_name, parent_phone, className, grade]
        );
        
        res.json({ success: true, id: result.lastID });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// إدارة الحضور
app.get('/api/attendance', async (req, res) => {
    try {
        const { date } = req.query;
        let sql = 'SELECT a.*, s.name as student_name FROM attendance a JOIN students s ON a.student_id = s.student_id';
        let params = [];
        
        if (date) {
            sql += ' WHERE a.date = ?';
            params = [date];
        }
        
        sql += ' ORDER BY a.created_at DESC';
        
        const attendance = await query(sql, params);
        res.json({ success: true, data: attendance });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/attendance', async (req, res) => {
    try {
        const { student_id, date, status, teacher_id, notes } = req.body;
        
        const result = await run(
            'INSERT INTO attendance (student_id, date, status, teacher_id, notes) VALUES (?, ?, ?, ?, ?)',
            [student_id, date, status, teacher_id, notes]
        );
        
        res.json({ success: true, id: result.lastID });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// إحصائيات سريعة
app.get('/api/dashboard/stats', async (req, res) => {
    try {
        const [students, attendanceToday, teachers, classes] = await Promise.all([
            query('SELECT COUNT(*) as count FROM students'),
            query('SELECT COUNT(*) as count FROM attendance WHERE date = ?', [new Date().toISOString().split('T')[0]]),
            query('SELECT COUNT(*) as count FROM teachers'),
            query('SELECT COUNT(*) as count FROM classes')
        ]);

        res.json({
            success: true,
            data: {
                totalStudents: students[0]?.count || 0,
                todayAttendance: attendanceToday[0]?.count || 0,
                totalTeachers: teachers[0]?.count || 0,
                totalClasses: classes[0]?.count || 0
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// API بوابة أولياء الأمور
app.get('/api/parent/child/:studentId', async (req, res) => {
    try {
        const { studentId } = req.params;
        
        const student = await query('SELECT * FROM students WHERE student_id = ?', [studentId]);
        
        if (student.length === 0) {
            return res.status(404).json({ error: 'الطالب غير موجود' });
        }
        
        const attendance = await query(
            'SELECT * FROM attendance WHERE student_id = ? ORDER BY date DESC LIMIT 30',
            [studentId]
        );
        
        res.json({
            success: true,
            data: {
                student: student[0],
                attendance: attendance
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =====================================================
// Middleware المصادقة
// =====================================================

function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    
    if (!token) {
        return res.status(401).json({ error: 'رمز المصادقة مطلوب' });
    }
    
    jwt.verify(token, process.env.JWT_SECRET || 'classroom_secret_2024', (err, user) => {
        if (err) {
            return res.status(403).json({ error: 'رمز المصادقة غير صالح' });
        }
        req.user = user;
        next();
    });
}

// API محمية
app.get('/api/admin/users', authenticateToken, async (req, res) => {
    if (req.user.role !== 'admin') {
        return res.status(403).json({ error: 'غير مصرح لك بالوصول' });
    }
    
    try {
        const users = await query('SELECT id, username, role, name, email, created_at FROM users');
        res.json({ success: true, data: users });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// =====================================================
// معالجة الأخطاء العامة
// =====================================================

app.use((err, req, res, next) => {
    console.error('خطأ غير معالج:', err);
    res.status(500).json({ 
        error: 'خطأ داخلي في الخادم',
        message: process.env.NODE_ENV === 'development' ? err.message : 'حدث خطأ'
    });
});

// معالجة طلبات غير موجودة
app.use('*', (req, res) => {
    res.status(404).json({ 
        error: 'الصفحة غير موجودة',
        path: req.originalUrl 
    });
});

// =====================================================
// بدء الخادم
// =====================================================

const PORT = process.env.PORT || 3000;

// تهيئة قاعدة البيانات ثم بدء الخادم
initializeDatabase().then(() => {
    app.listen(PORT, () => {
        console.log(`🚀 خادم نظام الفصول الدراسية يعمل على البورت ${PORT}`);
        console.log(`📊 نوع قاعدة البيانات: ${isVercel ? 'PostgreSQL' : 'SQLite'}`);
        console.log(`🌍 البيئة: ${process.env.NODE_ENV || 'development'}`);
        console.log(`⏰ وقت البدء: ${new Date().toLocaleString('ar-SA')}`);
    });
}).catch(error => {
    console.error('❌ فشل في تهيئة قاعدة البيانات:', error);
    process.exit(1);
});

// تصدير التطبيق لـ Vercel
module.exports = app;
