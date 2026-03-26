const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const path = require('path');

// DBS 26 Server v3.0.0 - SECURITY HARDENED
console.log('🚀 DBS 26 Server v3.0.0 starting...');
console.log('🛡️ Security mode: ENABLED');

// 🛡️ SECURITY MODULES (Optional - graceful fallback if not installed)
let rateLimit, helmet;
try {
    rateLimit = require('express-rate-limit');
    helmet = require('helmet');
    console.log('✅ Security modules loaded');
} catch (e) {
    console.log('⚠️ Security modules not found, running without rate limiting');
    rateLimit = null;
    helmet = null;
}

// 🛡️ SECURITY MIDDLEWARE
const limiter = rateLimit ? rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // limit each IP to 100 requests per windowMs
    message: {
        error: 'Too many requests from this IP, please try again later.',
        code: 'RATE_LIMIT_EXCEEDED'
    },
    standardHeaders: true,
    legacyHeaders: false,
}) : null;

// 🛡️ ANTI-CHEAT & SECURITY MANAGER - HARDENED v3.0
class SecurityManager {
    constructor() {
        this.suspiciousActivities = new Map();
        this.rateLimits = new Map();
        this.blockedIPs = new Set();
        this.playerValidation = new Map();
        this.ipConnectionCount = new Map(); // Track connections per IP
        this.globalRateLimit = new Map(); // Global rate limiting
    }
    
    // 🛡️ NEW: IP-based protection
    checkIPConnection(ip, maxConnections = 3) {
        const now = Date.now();
        
        if (!this.ipConnectionCount.has(ip)) {
            this.ipConnectionCount.set(ip, []);
        }
        
        const connections = this.ipConnectionCount.get(ip);
        connections.push(now);
        
        // Clean old connections (5 minutes)
        const filtered = connections.filter(t => now - t < 300000);
        this.ipConnectionCount.set(ip, filtered);
        
        if (filtered.length > maxConnections) {
            this.blockedIPs.add(ip);
            console.warn(`🚨 IP BLOCKED (too many connections): ${ip.split('.').slice(0, 2).join('.')}.***.***`);
            return false;
        }
        
        return true;
    }
    
    // 🛡️ NEW: Global rate limiting (all events)
    checkGlobalRateLimit(socketId, maxPerSecond = 50) {
        const now = Date.now();
        const key = `global_${socketId}`;
        
        if (!this.globalRateLimit.has(key)) {
            this.globalRateLimit.set(key, []);
        }
        
        const timestamps = this.globalRateLimit.get(key);
        timestamps.push(now);
        
        // Clean old timestamps (1 second)
        const filtered = timestamps.filter(t => now - t < 1000);
        this.globalRateLimit.set(key, filtered);
        
        if (filtered.length > maxPerSecond) {
            this.logSuspiciousActivity(socketId, 'GLOBAL_RATE_LIMIT', { count: filtered.length });
            return false;
        }
        
        return true;
    }
    
    // Rate limiting per socket
    checkRateLimit(socketId, action, maxPerMinute = 10) {
        const now = Date.now();
        const key = `${socketId}_${action}`;
        
        if (!this.rateLimits.has(key)) {
            this.rateLimits.set(key, []);
        }
        
        const timestamps = this.rateLimits.get(key);
        timestamps.push(now);
        
        // Clean old timestamps
        const filtered = timestamps.filter(t => now - t < 60000);
        this.rateLimits.set(key, filtered);
        
        if (filtered.length > maxPerMinute) {
            this.logSuspiciousActivity(socketId, 'RATE_LIMIT_EXCEEDED', { action, count: filtered.length });
            return false;
        }
        
        return true;
    }
    
    // Validate score changes
    validateScoreChange(socketId, oldScore, newScore, maxIncrease = 1) {
        const diff = newScore - oldScore;
        
        if (diff > maxIncrease || diff < 0) {
            this.logSuspiciousActivity(socketId, 'INVALID_SCORE_CHANGE', {
                oldScore, newScore, diff
            });
            return false;
        }
        
        return true;
    }
    
    // Validate game data
    validateGameData(socketId, data) {
        // Check for impossible values
        if (data.ballX && (data.ballX < -100 || data.ballX > 1000)) {
            this.logSuspiciousActivity(socketId, 'INVALID_BALL_POSITION', { ballX: data.ballX });
            return false;
        }
        
        if (data.ballY && (data.ballY < -100 || data.ballY > 600)) {
            this.logSuspiciousActivity(socketId, 'INVALID_BALL_POSITION', { ballY: data.ballY });
            return false;
        }
        
        // Check for impossible velocities
        if (data.ballVx && Math.abs(data.ballVx) > 50) {
            this.logSuspiciousActivity(socketId, 'INVALID_BALL_VELOCITY', { ballVx: data.ballVx });
            return false;
        }
        
        if (data.ballVy && Math.abs(data.ballVy) > 50) {
            this.logSuspiciousActivity(socketId, 'INVALID_BALL_VELOCITY', { ballVy: data.ballVy });
            return false;
        }
        
        return true;
    }
    
    // Log suspicious activity
    logSuspiciousActivity(socketId, type, data) {
        const now = Date.now();
        const key = socketId;
        
        if (!this.suspiciousActivities.has(key)) {
            this.suspiciousActivities.set(key, []);
        }
        
        const activities = this.suspiciousActivities.get(key);
        activities.push({
            type,
            data,
            timestamp: now
        });
        
        // Keep only last 50 activities per socket
        if (activities.length > 50) {
            activities.splice(0, activities.length - 50);
        }
        
        console.warn(`🚨 SECURITY ALERT [${socketId.slice(0, 8)}***]: ${type}`);
        
        // Auto-block after too many suspicious activities
        if (activities.length > 10) {
            const recentActivities = activities.filter(a => now - a.timestamp < 300000); // 5 minutes
            if (recentActivities.length > 5) {
                this.blockSocket(socketId);
            }
        }
    }
    
    // Block suspicious socket
    blockSocket(socketId) {
        this.blockedIPs.add(socketId);
        console.log(`🚨 SOCKET BLOCKED: ${socketId.slice(0, 8)}***`);
        
        // Auto-unblock after 10 minutes
        setTimeout(() => {
            this.blockedIPs.delete(socketId);
            console.log(`✅ Socket unblocked: ${socketId.slice(0, 8)}***`);
        }, 10 * 60 * 1000);
    }
    
    // Check if socket is blocked
    isBlocked(socketId) {
        return this.blockedIPs.has(socketId);
    }
    
    // Validate client data integrity
    validateClientData(data) {
        if (!data.timestamp || !data.clientVersion || !data.checksum) {
            return false;
        }
        
        // Check timestamp (not older than 30 seconds)
        const now = Date.now();
        if (now - data.timestamp > 30000) {
            return false;
        }
        
        // Validate checksum (basic integrity check)
        const originalData = { ...data };
        delete originalData.timestamp;
        delete originalData.clientVersion;
        delete originalData.checksum;
        
        const expectedChecksum = Buffer.from(JSON.stringify(originalData)).toString('base64').slice(0, 10);
        
        return data.checksum === expectedChecksum;
    }
}

const securityManager = new SecurityManager();

// Express app oluştur
const app = express();

// 🛡️ Apply security middleware (if available)
if (helmet) {
    app.use(helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "'unsafe-inline'", "https://cdn.socket.io"],
                styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
                fontSrc: ["'self'", "https://fonts.gstatic.com"],
                imgSrc: ["'self'", "data:", "https:"],
                connectSrc: ["'self'", "ws:", "wss:"]
            }
        }
    }));
}

if (limiter) {
    app.use(limiter);
}

// Add security headers
app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
});

const server = http.createServer(app);
const io = socketIO(server, {
    cors: {
        origin: process.env.ALLOWED_ORIGINS ? process.env.ALLOWED_ORIGINS.split(',') : ["*"],
        methods: ["GET", "POST"],
        credentials: false
    },
    // 🛡️ Socket.IO security options
    allowEIO3: false,
    transports: ['websocket', 'polling'],
    pingTimeout: 60000,
    pingInterval: 25000,
    // 🛡️ Max HTTP request body size
    maxHttpBufferSize: 1e5 // 100KB max
});

// Static dosyaları servis et (mevcut klasörden)
app.use(express.static(__dirname));

// Keep-alive endpoint - MINIMAL INFO
app.get('/keep-alive', (req, res) => {
    res.status(200).json({ 
        status: 'alive'
    });
});

// Ping endpoint - basit health check
app.get('/ping', (req, res) => {
    res.status(200).send('pong');
});

// Health check endpoint - MINIMAL INFO
app.get('/health', (req, res) => {
    res.status(200).json({ 
        status: 'ok',
        version: '3.0.0'
    });
});

// Oyuncu odaları için veri yapısı
let rooms = {};
let playerCount = 0;

// Online leaderboard - oyuncu istatistikleri (PERSISTENT)
let onlineLeaderboard = {}; // { playerName: { wins: 0, losses: 0, goals: 0, goalsAgainst: 0 } }

// 📁 Load leaderboard from file on startup
const fs = require('fs');
const LEADERBOARD_FILE = path.join(__dirname, 'leaderboard.json');

function loadLeaderboard() {
    try {
        if (fs.existsSync(LEADERBOARD_FILE)) {
            const data = fs.readFileSync(LEADERBOARD_FILE, 'utf8');
            onlineLeaderboard = JSON.parse(data);
            console.log(`✅ Leaderboard loaded: ${Object.keys(onlineLeaderboard).length} players`);
        }
    } catch (e) {
        console.log('⚠️ Could not load leaderboard, starting fresh');
        onlineLeaderboard = {};
    }
}

function saveLeaderboard() {
    try {
        fs.writeFileSync(LEADERBOARD_FILE, JSON.stringify(onlineLeaderboard, null, 2));
    } catch (e) {
        console.error('❌ Failed to save leaderboard:', e.message);
    }
}

// Load leaderboard on startup
loadLeaderboard();

// Save leaderboard every 30 seconds
setInterval(saveLeaderboard, 30000);

// Registered players and pending friend requests
let registeredPlayers = new Set(); // Players who have played at least once
let pendingFriendRequests = {}; // { playerName: [{ from, timestamp, id }] }

// Function to deliver pending friend requests when player comes online
function deliverPendingFriendRequests(socket, playerName) {
    if (pendingFriendRequests[playerName] && pendingFriendRequests[playerName].length > 0) {
        console.log(`📬 Delivering ${pendingFriendRequests[playerName].length} pending friend requests to ${playerName}`);
        
        pendingFriendRequests[playerName].forEach(request => {
            socket.emit('friend_request_received', {
                id: request.id,
                from: request.from,
                timestamp: request.timestamp
            });
        });
        
        // Clear delivered requests
        delete pendingFriendRequests[playerName];
    }
}

// 🛡️ Secure socket wrapper (simplified for compatibility)
function secureSocketHandler(socket, eventName, handler, rateLimit = 20) {
    socket.on(eventName, (data) => {
        // Check if socket is blocked
        if (securityManager.isBlocked(socket.id)) {
            console.warn(`🚨 Blocked socket attempted ${eventName}: ${socket.id}`);
            socket.emit('security_error', { message: 'Access denied', code: 'BLOCKED' });
            return;
        }
        
        // Rate limiting (more lenient)
        if (!securityManager.checkRateLimit(socket.id, eventName, rateLimit)) {
            console.warn(`⚠️ Rate limit for ${eventName}: ${socket.id}`);
            // Don't block, just warn
        }
        
        try {
            handler(data);
        } catch (error) {
            console.error(`Error in ${eventName}:`, error);
        }
    });
}

// Socket.IO bağlantısı
io.on('connection', (socket) => {
    const playerId = ++playerCount;
    const shortId = socket.id.slice(0, 8) + '***';
    console.log(`Player ${playerId} connected (${shortId})`);

    socket.playerId = playerId;
    socket.playerName = null;
    
    // 🛡️ Connection security check - IP MASKED FOR PRIVACY
    const clientIP = socket.handshake.address;
    const maskedIP = clientIP.split('.').slice(0, 2).join('.') + '.***.***';
    console.log(`🔍 Connection from: ${maskedIP}`);
    
    // 🛡️ NEW: Check if IP is blocked
    if (securityManager.blockedIPs.has(clientIP)) {
        console.warn(`🚨 Blocked IP attempted connection: ${maskedIP}`);
        socket.disconnect(true);
        return;
    }
    
    // 🛡️ NEW: IP-based connection limiting
    if (!securityManager.checkIPConnection(clientIP, 3)) {
        socket.disconnect(true);
        return;
    }
    
    // Track connection attempts per IP
    if (!securityManager.checkRateLimit(clientIP, 'connection', 5)) {
        console.warn(`🚨 Too many connections from: ${maskedIP}`);
        socket.disconnect(true);
        return;
    }

    // 🛡️ Secure event handlers
    secureSocketHandler(socket, 'create_room', (data) => {
        const roomId = `room_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
        const roomData = {
            id: roomId,
            name: data.roomName || `${data.playerName}'s Room`,
            host: {
                id: socket.id,
                playerId: playerId,
                name: data.playerName || `Player ${playerId}`
            },
            players: [{
                id: socket.id,
                playerId: playerId,
                name: data.playerName || `Player ${playerId}`,
                ready: false
            }],
            maxPlayers: data.maxPlayers || 2,
            gameMode: data.gameMode || '1v1',
            stadium: data.stadium || 'rf-stadium',
            weather: data.weather || 'normal',
            matchDuration: data.matchDuration || 120, // Saniye cinsinden
            isPrivate: data.isPrivate || false,
            password: data.password || null,
            status: 'waiting', // waiting, playing, finished
            createdAt: Date.now()
        };

        rooms[roomId] = roomData;
        socket.join(roomId);
        socket.currentRoom = roomId;
        socket.playerName = data.playerName;
        
        // Register player and deliver pending friend requests
        registeredPlayers.add(data.playerName);
        deliverPendingFriendRequests(socket, data.playerName);

        socket.emit('room_created', { roomId, room: roomData });
        broadcastRoomList();

        console.log(`Room created: ${roomId.slice(0, 15)}*** by ${data.playerName}`);
    }, 2); // Max 2 room creations per minute

    // Oda listesini al
    socket.on('get_rooms', () => {
        const publicRooms = Object.values(rooms).filter(r => !r.isPrivate && r.status === 'waiting');
        socket.emit('rooms_list', publicRooms);
    });

    // Odaya katıl
    secureSocketHandler(socket, 'join_room', (data) => {
        console.log('📥 Join room request:', data);
        
        const room = rooms[data.roomId];
        
        if (!room) {
            console.log('❌ Room not found:', data.roomId);
            socket.emit('join_error', { message: 'Oda bulunamadı' });
            return;
        }

        if (room.status !== 'waiting') {
            console.log('❌ Game already started');
            socket.emit('join_error', { message: 'Oyun zaten başlamış' });
            return;
        }

        if (room.players.length >= room.maxPlayers) {
            console.log('❌ Room full');
            socket.emit('join_error', { message: 'Oda dolu' });
            return;
        }

        if (room.password && room.password !== data.password) {
            console.log('❌ Wrong password');
            socket.emit('join_error', { message: 'Yanlış şifre' });
            return;
        }

        const player = {
            id: socket.id,
            playerId: playerId,
            name: data.playerName || `Player ${playerId}`,
            ready: false
        };

        room.players.push(player);
        socket.join(data.roomId);
        socket.currentRoom = data.roomId;
        socket.playerName = data.playerName;
        
        // Register player and deliver pending friend requests
        registeredPlayers.add(data.playerName);
        deliverPendingFriendRequests(socket, data.playerName);

        // Odadaki herkese bildir
        io.to(data.roomId).emit('player_joined', { player, room });
        socket.emit('room_joined', { room });
        broadcastRoomList();

        console.log(`✅ ${data.playerName} joined room ${data.roomId}`);
    });

    // Hazır durumu değiştir
    socket.on('toggle_ready', () => {
        if (!socket.currentRoom) return;
        
        const room = rooms[socket.currentRoom];
        if (!room) return;

        const player = room.players.find(p => p.id === socket.id);
        if (player) {
            player.ready = !player.ready;
            io.to(socket.currentRoom).emit('player_ready_changed', { playerId: player.playerId, ready: player.ready, room });

            // Tüm oyuncular hazırsa oyunu başlat
            if (room.players.length >= 2 && room.players.every(p => p.ready)) {
                startGame(room);
            }
        }
    });

    // Oyun güncellemesi - pozisyon ve top bilgisi
    socket.on('game_update', (data) => {
        if (!socket.currentRoom) return;
        
        // Performans için log yok (çok sık çağrılıyor)
        socket.to(socket.currentRoom).emit('game_update', {
            playerId: socket.playerId,
            ...data
        });
    });
    
    // New player sync system - optimized
    socket.on('player_sync', (data) => {
        if (!socket.currentRoom) return;
        
        // Forward to opponent with sender ID and timestamp
        socket.to(socket.currentRoom).emit('player_sync', {
            playerId: socket.playerId,
            x: data.x,
            y: data.y,
            vx: data.vx,
            vy: data.vy,
            timestamp: Date.now()
        });
    });

    // Top dokunma - hem host hem guest için
    socket.on('ball_touch', (data) => {
        if (!socket.currentRoom) return;
        const room = rooms[socket.currentRoom];
        if (!room) return;
        
        const isHost = room.host && room.host.id === socket.id;
        const playerType = isHost ? 'HOST' : 'GUEST';
        
        console.log(`⚽ ${playerType} topa dokundu:`, {
            ball: `(${data.ballX}, ${data.ballY})`,
            velocity: `(${data.ballVx}, ${data.ballVy})`,
            isHost: data.isHost
        });
        
        // Diğer oyuncuya gönder (broadcast)
        socket.to(socket.currentRoom).emit('ball_touch', {
            playerId: socket.playerId,
            ballX: data.ballX,
            ballY: data.ballY,
            ballVx: data.ballVx,
            ballVy: data.ballVy,
            timestamp: data.timestamp,
            isHost: data.isHost
        });
    });

    // Ball sync - sürekli pozisyon güncellemesi
    socket.on('ball_sync', (data) => {
        if (!socket.currentRoom) return;
        // Diğer oyuncuya gönder (yüksek frekanslı, log yok)
        socket.to(socket.currentRoom).emit('ball_sync', {
            ballX: data.ballX,
            ballY: data.ballY,
            ballVx: data.ballVx,
            ballVy: data.ballVy,
            isHost: data.isHost,
            timestamp: Date.now()
        });
    });
    
    // Time sync - HOST gameTime broadcast eder
    socket.on('time_sync', (data) => {
        if (!socket.currentRoom) return;
        // HOST'tan GUEST'e gameTime sync
        socket.to(socket.currentRoom).emit('time_sync', {
            gameTime: data.gameTime,
            playerScore: data.playerScore,
            aiScore: data.aiScore
        });
    });

    // 🛡️ Gol güncelleme - skor her iki oyuncuya da gönderilir
    secureSocketHandler(socket, 'goal_update', (data) => {
        if (!socket.currentRoom) return;
        const room = rooms[socket.currentRoom];
        if (!room) return;

        console.log(`⚽ GOL! Room: ${socket.currentRoom}, Skor: ${data.playerScore}-${data.aiScore}, Scorer: ${data.scorer}`);
        
        // 🛡️ Validate score data
        if (!securityManager.validateGameData(socket.id, data)) {
            console.warn(`🚨 Invalid goal data from ${socket.id}`);
            return;
        }
        
        // Validate score values
        if (data.playerScore < 0 || data.aiScore < 0 || 
            data.playerScore > 50 || data.aiScore > 50) {
            securityManager.logSuspiciousActivity(socket.id, 'INVALID_SCORE_VALUES', data);
            return;
        }

        // Odadaki HERKESE (gönderende dahil) skor güncellemesini yayınla
        io.to(socket.currentRoom).emit('goal_update', {
            playerScore: data.playerScore,
            aiScore: data.aiScore,
            scorer: data.scorer,
            timestamp: Date.now()
        });
    }, 5); // Max 5 goals per minute

    // Replay başlat - host replay başlattığında diğer oyunculara bildir
    socket.on('start_replay', (data) => {
        if (!socket.currentRoom) {
            console.log('❌ REPLAY EVENT: No room!');
            return;
        }
        
        const room = rooms[socket.currentRoom];
        if (!room) {
            console.log('❌ REPLAY EVENT: Room not found!');
            return;
        }
        
        console.log(`🎬 REPLAY EVENT RECEIVED from ${socket.playerName} in room ${socket.currentRoom}`);
        console.log(`   Scorer: ${data.scorer}`);
        console.log(`   Players in room: ${room.players.map(p => p.name).join(', ')}`);
        
        // SADECE DİĞER OYUNCULARA replay başladığını bildir (host kendi replay'ini başlatıyor)
        socket.to(socket.currentRoom).emit('replay_started', {
            scorer: data.scorer
        });
        
        console.log(`   ✅ Replay event sent to other players in room ${socket.currentRoom}`);
    });

    // Half-time - host half-time'a girdiğinde diğer oyunculara bildir
    socket.on('half_time', (data) => {
        if (!socket.currentRoom) return;
        const room = rooms[socket.currentRoom];
        if (!room) return;
        
        console.log(`⏸️ HALF-TIME in room ${socket.currentRoom}, scores: ${data.playerScore}-${data.aiScore}`);
        
        // Reset half-time ready status
        room.halfTimeReady = new Set();
        
        // TÜM oyunculara (host dahil) half-time'ı bildir
        io.to(socket.currentRoom).emit('half_time_started', {
            playerScore: data.playerScore,
            aiScore: data.aiScore
        });
    });
    
    // Half-time ready
    socket.on('half_time_ready', () => {
        if (!socket.currentRoom) return;
        const room = rooms[socket.currentRoom];
        if (!room) return;
        
        // Initialize if not exists
        if (!room.halfTimeReady) {
            room.halfTimeReady = new Set();
        }
        
        // Add player to ready set
        room.halfTimeReady.add(socket.id);
        
        const readyCount = room.halfTimeReady.size;
        const totalPlayers = room.players.length;
        
        console.log(`⏸️ Half-time ready: ${readyCount}/${totalPlayers} in room ${socket.currentRoom}`);
        
        // Broadcast ready status
        io.to(socket.currentRoom).emit('half_time_ready_update', {
            readyCount: readyCount,
            totalPlayers: totalPlayers
        });
        
        // If all players ready, resume game
        if (readyCount >= totalPlayers) {
            console.log(`⚽ All players ready, resuming game in room ${socket.currentRoom}`);
            io.to(socket.currentRoom).emit('half_time_resume');
            room.halfTimeReady.clear();
        }
    });

    // Emoji gönderme
    socket.on('send_emoji', (data) => {
        if (!socket.currentRoom) return;
        console.log(`😎 Player ${socket.playerId} (${socket.playerName}) sent emoji: ${data.emoji}`);
        socket.to(socket.currentRoom).emit('emoji_received', {
            playerId: socket.playerId,
            playerName: socket.playerName,
            emoji: data.emoji
        });
    });

    // Oyun bitişi - skor güncelleme
    socket.on('game_end', (data) => {
        if (!socket.currentRoom) return;
        const room = rooms[socket.currentRoom];
        if (!room) return;

        // Room status'ünü 'waiting'e çevir
        room.status = 'waiting';
        
        // Tüm oyuncuları 'not ready' yap
        room.players.forEach(p => p.ready = false);
        
        // Odadaki herkese güncel room'u gönder
        io.to(socket.currentRoom).emit('room_updated', { room });
        
        broadcastRoomList();

        // Her oyuncunun skorunu güncelle
        data.players.forEach(player => {
            if (!onlineLeaderboard[player.name]) {
                onlineLeaderboard[player.name] = {
                    name: player.name,
                    wins: 0,
                    losses: 0,
                    goals: 0,
                    goalsAgainst: 0,
                    gamesPlayed: 0
                };
            }

            const stats = onlineLeaderboard[player.name];
            stats.gamesPlayed++;
            stats.goals += player.score || 0;
            stats.goalsAgainst += player.opponentScore || 0;

            if (player.won) {
                stats.wins++;
            } else {
                stats.losses++;
            }
        });

        console.log(`Game ended in room ${socket.currentRoom}`, data);
    });

    // Offline maç sonucu - AI'ya karşı oynanan maçlar
    socket.on('offline_match_result', (data) => {
        const playerName = data.playerName;
        if (!playerName) return;
        
        // Register player and deliver pending friend requests if not already set
        if (!socket.playerName) {
            socket.playerName = playerName;
            registeredPlayers.add(playerName);
            deliverPendingFriendRequests(socket, playerName);
        }
        
        if (!onlineLeaderboard[playerName]) {
            onlineLeaderboard[playerName] = {
                name: playerName,
                wins: 0,
                losses: 0,
                goals: 0,
                goalsAgainst: 0,
                gamesPlayed: 0
            };
        }

        const stats = onlineLeaderboard[playerName];
        stats.gamesPlayed++;
        stats.goals += data.playerScore || 0;
        stats.goalsAgainst += data.aiScore || 0;

        if (data.won) {
            stats.wins++;
        } else if (data.lost) {
            stats.losses++;
        }

        console.log(`📊 Offline match result: ${playerName} - ${data.playerScore}:${data.aiScore} (${data.won ? 'WIN' : data.lost ? 'LOSS' : 'DRAW'})`);
        
        // Save leaderboard after each match
        saveLeaderboard();
    });

    // Leaderboard al
    socket.on('get_leaderboard', () => {
        const leaderboardArray = Object.values(onlineLeaderboard)
            .sort((a, b) => {
                // Önce kazanma sayısına göre sırala
                if (b.wins !== a.wins) return b.wins - a.wins;
                // Eşitse gol farkına göre
                const aGoalDiff = a.goals - a.goalsAgainst;
                const bGoalDiff = b.goals - b.goalsAgainst;
                if (bGoalDiff !== aGoalDiff) return bGoalDiff - aGoalDiff;
                // Eşitse atılan gol sayısına göre
                return b.goals - a.goals;
            })
            .slice(0, 10); // İlk 10 oyuncu

        socket.emit('leaderboard_data', leaderboardArray);
    });

    // Friend System Events
    socket.on('send_friend_request', (data) => {
        const { from, to } = data;
        console.log(`👥 Friend request: ${from} -> ${to}`);
        
        // Register both players as they've interacted with the system
        registeredPlayers.add(from);
        registeredPlayers.add(to);
        
        // Find target player
        const targetSocket = Array.from(io.sockets.sockets.values())
            .find(s => s.playerName === to);
        
        if (targetSocket) {
            // Player is online - deliver immediately
            const requestId = Date.now().toString();
            targetSocket.emit('friend_request_received', {
                id: requestId,
                from: from,
                timestamp: Date.now()
            });
            console.log(`✅ Friend request delivered to ${to} (online)`);
        } else {
            // Player is offline - store for later delivery
            if (!pendingFriendRequests[to]) {
                pendingFriendRequests[to] = [];
            }
            
            const requestId = Date.now().toString();
            pendingFriendRequests[to].push({
                id: requestId,
                from: from,
                timestamp: Date.now()
            });
            
            console.log(`📬 Friend request stored for ${to} (offline)`);
            socket.emit('friend_request_sent', {
                message: `Friend request sent to ${to}! They will receive it when they come online.`
            });
        }
    });
    
    socket.on('accept_friend_request', (data) => {
        const { from, to } = data;
        console.log(`✅ Friend request accepted: ${from} accepted ${to}`);
        
        // Notify the original sender
        const targetSocket = Array.from(io.sockets.sockets.values())
            .find(s => s.playerName === to);
        
        if (targetSocket) {
            targetSocket.emit('friend_request_accepted', {
                from: from
            });
        }
    });
    
    socket.on('decline_friend_request', (data) => {
        const { from, to } = data;
        console.log(`❌ Friend request declined: ${from} declined ${to}`);
        
        // Notify the original sender
        const targetSocket = Array.from(io.sockets.sockets.values())
            .find(s => s.playerName === to);
        
        if (targetSocket) {
            targetSocket.emit('friend_request_declined', {
                from: from
            });
        }
    });
    
    socket.on('remove_friend', (data) => {
        const { from, to } = data;
        console.log(`💔 Friend removed: ${from} removed ${to}`);
        
        // Notify the removed friend
        const targetSocket = Array.from(io.sockets.sockets.values())
            .find(s => s.playerName === to);
        
        if (targetSocket) {
            targetSocket.emit('friend_removed', {
                from: from
            });
        }
    });
    
    socket.on('send_game_invite', (data) => {
        const { from, to, roomId, roomName } = data;
        console.log(`🎮 Game invite: ${from} invited ${to} to room ${roomName}`);
        
        // Find target player
        const targetSocket = Array.from(io.sockets.sockets.values())
            .find(s => s.playerName === to);
        
        if (targetSocket) {
            const inviteId = Date.now().toString();
            targetSocket.emit('game_invite_received', {
                id: inviteId,
                from: from,
                roomId: roomId,
                roomName: roomName,
                timestamp: Date.now()
            });
            console.log(`✅ Game invite delivered to ${to}`);
        } else {
            socket.emit('game_invite_failed', {
                message: 'Player not found or offline'
            });
            console.log(`❌ Game invite failed: ${to} not online`);
        }
    });
    
    socket.on('get_online_friends', (data) => {
        const { friendNames } = data;
        const onlineFriends = [];
        
        friendNames.forEach(friendName => {
            const friendSocket = Array.from(io.sockets.sockets.values())
                .find(s => s.playerName === friendName);
            
            if (friendSocket) {
                onlineFriends.push(friendName);
            }
        });
        
        socket.emit('online_friends_update', { onlineFriends });
    });
    
    // Second half start - synchronize all players
    socket.on('second_half_start', () => {
        if (!socket.currentRoom) return;
        
        console.log(`⚽ Second half started in room ${socket.currentRoom}`);
        
        // Notify all players in the room (including sender)
        io.to(socket.currentRoom).emit('second_half_started');
    });

    // Odadan ayrıl
    socket.on('leave_room', () => {
        leaveRoom(socket);
    });

    // 🛡️ Security alert handler
    secureSocketHandler(socket, 'security_alert', (data) => {
        console.warn(`🚨 Client security alert from ${socket.id}:`, data);
        securityManager.logSuspiciousActivity(socket.id, 'CLIENT_SECURITY_ALERT', data);
    }, 3);

    // Bağlantı kesildiğinde
    socket.on('disconnect', () => {
        console.log(`Player ${playerId} disconnected`);
        leaveRoom(socket);
    });
});

// Oyunu başlat
function startGame(room) {
    room.status = 'playing';
    room.gameStartTime = Date.now();
    
    io.to(room.id).emit('game_start', {
        room,
        players: room.players
    });
    
    broadcastRoomList();
    console.log(`Game started in room ${room.id}`);
}

// Odadan ayrıl
function leaveRoom(socket) {
    if (!socket.currentRoom) return;
    
    const room = rooms[socket.currentRoom];
    if (!room) return;

    const wasHost = room.host.id === socket.id;
    const wasPlaying = room.status === 'playing';
    const roomId = socket.currentRoom;

    // Önce mesajları gönder, sonra oyuncuyu çıkar
    if (wasHost) {
        // Host ayrılıyor - tüm oyunculara bildir
        if (wasPlaying) {
            console.log(`Host left during game in room ${roomId}, closing room`);
            io.to(roomId).emit('host_left_game', {
                message: 'Oda sahibi oyundan ayrıldı'
            });
        } else {
            console.log(`Host left lobby in room ${roomId}, closing room`);
            io.to(roomId).emit('host_left_lobby', {
                message: 'Oda sahibi odadan ayrıldı'
            });
        }
        // Host ayrılırsa odayı sil
        delete rooms[roomId];
    } else {
        // Normal oyuncu ayrılıyor
        // Sonra oyuncuyu çıkar
        room.players = room.players.filter(p => p.id !== socket.id);
        
        // Oda boşaldıysa sil
        if (room.players.length === 0) {
            delete rooms[roomId];
            console.log(`Room ${roomId} deleted (empty)`);
        } else {
            // Hala oyuncu varsa mesajı gönder
            io.to(roomId).emit('player_left', {
                playerId: socket.playerId,
                playerName: socket.playerName,
                wasPlaying: wasPlaying,
                room: room
            });
        }
    }
    
    socket.leave(roomId);
    socket.currentRoom = null;
    broadcastRoomList();
}

// Oda listesini yayınla
function broadcastRoomList() {
    const publicRooms = Object.values(rooms).filter(r => !r.isPrivate && r.status === 'waiting');
    io.emit('rooms_list', publicRooms);
}

// Eski/inactive odaları temizle
function cleanupOldRooms() {
    const now = Date.now();
    const WAITING_TIMEOUT = 5 * 60 * 1000; // 5 dakika
    const PLAYING_TIMEOUT = 30 * 60 * 1000; // 30 dakika
    
    Object.keys(rooms).forEach(roomId => {
        const room = rooms[roomId];
        const age = now - room.createdAt;
        
        // Waiting status'ta 5 dakikadan eski odalar
        if (room.status === 'waiting' && age > WAITING_TIMEOUT) {
            console.log(`🧹 Cleaning up old waiting room: ${roomId} (${Math.round(age/1000/60)} mins old)`);
            // Odadaki herkese bildir
            io.to(roomId).emit('room_closed', { message: 'Room closed due to inactivity' });
            delete rooms[roomId];
            return;
        }
        
        // Playing status'ta 30 dakikadan eski odalar
        if (room.status === 'playing' && age > PLAYING_TIMEOUT) {
            console.log(`🧹 Cleaning up old playing room: ${roomId} (${Math.round(age/1000/60)} mins old)`);
            io.to(roomId).emit('room_closed', { message: 'Room closed due to timeout' });
            delete rooms[roomId];
            return;
        }
    });
    
    broadcastRoomList();
}

// Her 2 dakikada bir eski odaları temizle
setInterval(cleanupOldRooms, 2 * 60 * 1000);

// Clean up old pending friend requests (older than 7 days)
function cleanupOldFriendRequests() {
    const now = Date.now();
    const WEEK_IN_MS = 7 * 24 * 60 * 60 * 1000; // 7 days
    
    Object.keys(pendingFriendRequests).forEach(playerName => {
        pendingFriendRequests[playerName] = pendingFriendRequests[playerName].filter(request => {
            return (now - request.timestamp) < WEEK_IN_MS;
        });
        
        // Remove empty arrays
        if (pendingFriendRequests[playerName].length === 0) {
            delete pendingFriendRequests[playerName];
        }
    });
}

// Clean up old friend requests every 24 hours
setInterval(cleanupOldFriendRequests, 24 * 60 * 60 * 1000);

// ⚡ KEEP-ALIVE ENDPOINT - Minimal info for security
app.get('/ping', (req, res) => {
    res.status(200).json({ status: 'alive' });
});

// Self-ping every 10 minutes to keep server awake
setInterval(() => {
    const http = require('http');
    const options = {
        hostname: 'localhost',
        port: PORT,
        path: '/ping',
        method: 'GET'
    };
    
    const req = http.request(options, (res) => {
        console.log(`⚡ Keep-alive ping: ${res.statusCode}`);
    });
    
    req.on('error', (error) => {
        console.error('⚠️ Keep-alive ping error:', error.message);
    });
    
    req.end();
}, 10 * 60 * 1000); // Her 10 dakikada bir

// Sunucuyu başlat
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`🎮 DBS 26 Server v3.0.0 running`);
    console.log(`�️ Security hardened mode active`);
});

// Temizlik için
process.on('SIGINT', () => {
    console.log('\n Shutting down server...');
    io.close();
    server.close();
    process.exit(0);
});