import express from 'express';
import crypto from 'crypto';
import dotenv from 'dotenv';
import cors from 'cors';

dotenv.config();

const app = express();
const PORT = process.env.PORT || 3001;

// Rate limiting
const rateLimit = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const MAX_REQUESTS_PER_WINDOW = 20;

// Content filter for child safety
const INAPPROPRIATE_PATTERNS = [
  /\b(violence|violent|kill|death|die|dead|suicide|drug|alcohol|sex|nude|porn)\b/gi,
  /\b(hate|racist|discrimination)\b/gi,
  /\b(damn|hell|shit|fuck|ass|bitch)\b/gi
];

function filterInappropriateContent(text) {
  for (const pattern of INAPPROPRIATE_PATTERNS) {
    if (pattern.test(text)) {
      return {
        safe: false,
        reason: 'Content contains inappropriate material for children'
      };
    }
  }
  return { safe: true };
}

// Middleware - Use cors module with function-based origin checking
app.use(cors({
  origin: function(origin, callback) {
    // Development origins
    const devOrigins = [
      'http://localhost:5173',
      'http://localhost:5174',
      'http://localhost:5175',
      'http://localhost:5176',
      'http://localhost:3000'
    ];

    // Production origins - always allow Capacitor
    const prodOrigins = [
      'capacitor://localhost',
      'ionic://localhost'
    ];

    // Combine all allowed origins
    const allowedOrigins = [...devOrigins, ...prodOrigins];

    // Allow requests with no origin (like mobile apps or curl requests)
    if (!origin) return callback(null, true);

    if (allowedOrigins.includes(origin)) {
      return callback(null, true);
    } else {
      return callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));

app.use(express.json());

// Rate limiting middleware
app.use((req, res, next) => {
  const clientId = req.ip;
  const now = Date.now();

  if (!rateLimit.has(clientId)) {
    rateLimit.set(clientId, { count: 1, resetTime: now + RATE_LIMIT_WINDOW });
    return next();
  }

  const limit = rateLimit.get(clientId);

  if (now > limit.resetTime) {
    limit.count = 1;
    limit.resetTime = now + RATE_LIMIT_WINDOW;
    rateLimit.set(clientId, limit);
    return next();
  }

  if (limit.count >= MAX_REQUESTS_PER_WINDOW) {
    return res.status(429).json({
      error: 'Too many requests. Please try again later.',
      retryAfter: Math.ceil((limit.resetTime - now) / 1000)
    });
  }

  limit.count++;
  rateLimit.set(clientId, limit);
  next();
});

// Session validation
const sessions = new Map();
const SESSION_DURATION = 30 * 60 * 1000; // 30 minutes

function generateSessionToken() {
  return crypto.randomBytes(32).toString('hex');
}

// Initialize session endpoint
app.post('/api/session/init', (req, res) => {
  const token = generateSessionToken();
  const sessionData = {
    createdAt: Date.now(),
    requestCount: 0,
    dailyUsage: 0
  };

  sessions.set(token, sessionData);

  // Clean old sessions
  for (const [key, value] of sessions.entries()) {
    if (Date.now() - value.createdAt > SESSION_DURATION) {
      sessions.delete(key);
    }
  }

  res.json({
    token,
    expiresIn: SESSION_DURATION / 1000 // seconds
  });
});

// Validate session middleware
function validateSession(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');

  if (!token || !sessions.has(token)) {
    return res.status(401).json({ error: 'Invalid or expired session' });
  }

  const session = sessions.get(token);

  if (Date.now() - session.createdAt > SESSION_DURATION) {
    sessions.delete(token);
    return res.status(401).json({ error: 'Session expired' });
  }

  session.requestCount++;

  // Daily usage limit (100 requests per day)
  const dayStart = new Date().setHours(0,0,0,0);
  if (session.createdAt >= dayStart) {
    session.dailyUsage++;
    if (session.dailyUsage > 100) {
      return res.status(429).json({
        error: 'Daily usage limit reached. Please try again tomorrow.'
      });
    }
  } else {
    session.dailyUsage = 1;
  }

  req.session = session;
  next();
}

// DeepSeek API proxy endpoint
app.post('/api/chat', validateSession, async (req, res) => {
  try {
    const { messages, options = {} } = req.body;

    if (!messages || !Array.isArray(messages)) {
      return res.status(400).json({ error: 'Invalid request format' });
    }

    // Check last message for inappropriate content
    const lastMessage = messages[messages.length - 1];
    if (lastMessage && lastMessage.role === 'user') {
      const contentCheck = filterInappropriateContent(lastMessage.content);
      if (!contentCheck.safe) {
        return res.status(400).json({
          error: 'Request blocked',
          reason: contentCheck.reason
        });
      }
    }

    // Make request to DeepSeek API
    const response = await fetch('https://api.deepseek.com/chat/completions', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${process.env.DEEPSEEK_API_KEY}`
      },
      body: JSON.stringify({
        model: options.model || 'deepseek-chat',
        messages,
        temperature: Math.min(options.temperature || 0.7, 0.9), // Cap temperature
        top_p: options.top_p || 0.95,
        max_tokens: Math.min(options.max_tokens || 1000, 2000) // Limit tokens
        // Removed response_format - DeepSeek no longer supports it
      })
    });

    if (!response.ok) {
      const error = await response.text();
      console.error('DeepSeek API error:', error);
      return res.status(response.status).json({
        error: 'AI service temporarily unavailable'
      });
    }

    const data = await response.json();

    // Filter response content
    if (data.choices && data.choices[0] && data.choices[0].message) {
      const responseContent = data.choices[0].message.content;
      const responseCheck = filterInappropriateContent(responseContent);

      if (!responseCheck.safe) {
        console.warn('Filtered inappropriate AI response');
        data.choices[0].message.content = "I cannot provide that information. Let's focus on your homework and learning instead!";
      }
    }

    res.json(data);

  } catch (error) {
    console.error('Proxy error:', error);
    res.status(500).json({
      error: 'Service error',
      message: 'Please try again later'
    });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});

// Usage stats endpoint (for parents)
app.get('/api/stats/:token', (req, res) => {
  const { token } = req.params;

  if (!sessions.has(token)) {
    return res.status(404).json({ error: 'Session not found' });
  }

  const session = sessions.get(token);
  res.json({
    requestCount: session.requestCount,
    dailyUsage: session.dailyUsage,
    sessionAge: Math.floor((Date.now() - session.createdAt) / 1000 / 60) // minutes
  });
});

app.listen(PORT, () => {
  console.log(`[OK] Vibe-Tutor API server running on port ${PORT}`);
  console.log('[OK] API key is secured server-side');
  console.log('[OK] Rate limiting enabled');
  console.log('[OK] Content filtering active');
});