// Server Software: Node.js and Express.js (cite: 611)

const express = require('express');
const app = express();
const port = process.env.PORT || 3000;
const { v4: uuidv4 } = require('uuid');

// Mock Database (In-memory storage for prototype)
let mockSessionsDB = [
    { id: uuidv4(), tutorId: 'tutor-1', date: '2025-12-05', time: '10:00', topic: 'Quantum Mechanics', capacity: 5, booked: 2 },
    { id: uuidv4(), tutorId: 'tutor-2', date: '2025-12-06', time: '14:00', topic: 'Classical Physics', capacity: 1, booked: 1 },
];
let mockUsersDB = { 'admin-1': { role: 'Admin', name: 'Admin Doe' }, 'tutor-1': { role: 'Tutor', name: 'Dr. Smith' }, 'student-1': { role: 'Student', name: 'Student John' } };


app.use(express.json()); // To parse JSON bodies
app.use(express.static('public')); // Serve static files (like the HTML above)

// Mock Middleware for Authentication & Access Control (cite: 870, 966)
const mockAuth = (req, res, next) => {
    // In a real system, this would validate a JWT or session token.
    // For the prototype, we assume user ID is passed in the header for simplicity.
    const userId = req.headers['x-user-id'] || 'admin-1'; 
    req.user = mockUsersDB[userId] || { role: 'Guest' };
    if (req.user.role === 'Guest') {
        return res.status(401).send({ message: 'Unauthorized access.' });
    }
    console.log(`[AuthService] User ${req.user.name} (${req.user.role}) is authenticated.`);
    next();
};

// --- Application Layer Endpoints (Simulating Business Logic) ---

// Feature: Session Scheduling (Tutor only) (cite: 635, 872)
app.post('/api/sessions', mockAuth, (req, res) => {
    if (req.user.role !== 'Tutor') {
        return res.status(403).send({ message: 'Only Tutors can create sessions.' }); // RoleAccessControl (cite: 970)
    }

    const { date, time, topic, capacity } = req.body;

    // Simulate Clash Detection (cite: 549, 875)
    const clash = mockSessionsDB.some(session => 
        session.tutorId === req.headers['x-user-id'] && session.date === date && session.time === time
    );

    if (clash) {
        return res.status(409).send({ message: 'Scheduling conflict detected. Tutor is busy at this time.' });
    }

    const newSession = {
        id: uuidv4(),
        tutorId: req.headers['x-user-id'],
        date,
        time,
        topic,
        capacity: parseInt(capacity),
        booked: 0
    };
    mockSessionsDB.push(newSession);

    // Simulate Email/Notification Trigger (cite: 891)
    console.log(`[NotificationSystem] Confirmation sent for new session: ${newSession.id}`);
    
    // Acceptance criteria 1: Session creation success within 10s (mocked by instant response) (cite: 639)
    res.status(201).send({ message: 'Session created successfully.', session: newSession }); 
});

// Feature: Session Booking (Student only) (cite: 636, 877)
app.post('/api/sessions/:id/book', mockAuth, (req, res) => {
    if (req.user.role !== 'Student') {
        return res.status(403).send({ message: 'Only Students can book sessions.' });
    }

    const session = mockSessionsDB.find(s => s.id === req.params.id);

    if (!session) {
        return res.status(404).send({ message: 'Session not found.' });
    }

    if (session.booked >= session.capacity) {
        return res.status(400).send({ message: 'Session is fully booked.' });
    }

    // Simulate transaction and update (cite: 721)
    session.booked++;
    // In a real DB: CREATE new Booking entity (cite: 990)

    // Simulate Notification Trigger (cite: 667)
    console.log(`[NotificationSystem] Confirmation sent to student: ${req.user.name} for session ID: ${session.id}`);

    // Acceptance criteria 2: Session selection success within 10s (mocked by instant response) (cite: 640)
    res.send({ message: 'Session booked successfully.', session });
});

// Feature: Admin Report Generation (Admin only) (cite: 681, 946)
app.get('/api/admin/reports', mockAuth, (req, res) => {
    if (req.user.role !== 'Admin') {
        return res.status(403).send({ message: 'Only Admins can generate reports.' });
    }

    // Simulate ReportGenerator compiling statistics (cite: 884)
    const report = {
        totalSessions: mockSessionsDB.length,
        totalBookedSlots: mockSessionsDB.reduce((sum, s) => sum + s.booked, 0),
        reportGenerated: new Date().toISOString()
    };
    
    // Acceptance criteria 2: Report generated within 10 seconds (mocked by instant response) (cite: 686)
    res.send({ message: 'Report generated successfully.', report });
});


// Start the server
app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
    console.log('Prototype running in web-based environment. (cite: 573)');
    console.log('Use client-side (index.html) for UI demonstration.');
});