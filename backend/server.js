/**
 * Mental Wellness Tracker — Backend Server
 * PromptWars Hackathon Challenge
 * 
 * Express.js server with Gemini AI integration for personalized
 * mental wellness support for exam-preparing students.
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { v4: uuidv4 } = require('uuid');
const { GoogleGenerativeAI } = require('@google/generative-ai');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, '..')));

// ─── Data Persistence (JSON Files) ────────────────────────────────────
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const USER_DATA_DIR = path.join(DATA_DIR, 'users');

function ensureDataDir() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(USERS_FILE)) fs.writeFileSync(USERS_FILE, '[]');
  if (!fs.existsSync(USER_DATA_DIR)) fs.mkdirSync(USER_DATA_DIR, { recursive: true });
}
ensureDataDir();

function readJSON(filePath) {
  try {
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return [];
  }
}

function writeJSON(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2));
}

function getUserFilePath(userId, fileName) {
  const userDir = path.join(USER_DATA_DIR, userId);
  if (!fs.existsSync(userDir)) {
    fs.mkdirSync(userDir, { recursive: true });
  }
  const filePath = path.join(userDir, fileName);
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, fileName === 'profile.json' ? '{}' : '[]');
  }
  return filePath;
}

// ─── Hashing Helpers ──────────────────────────────────────────────────
function hashPassword(password, salt) {
  return crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
}

function generateSalt() {
  return crypto.randomBytes(16).toString('hex');
}

// ─── Token Helpers ────────────────────────────────────────────────────
function generateToken(userId) {
  const payload = { userId, createdAt: Date.now() };
  return Buffer.from(JSON.stringify(payload)).toString('base64');
}

function verifyToken(token) {
  try {
    const payload = JSON.parse(Buffer.from(token, 'base64').toString('utf8'));
    // 7 days expiration
    if (Date.now() - payload.createdAt > 7 * 24 * 60 * 60 * 1000) {
      return null;
    }
    return payload.userId;
  } catch (e) {
    return null;
  }
}

// ─── Auth Middleware ──────────────────────────────────────────────────
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication token is required' });
  }

  const userId = verifyToken(token);
  if (!userId) {
    return res.status(403).json({ error: 'Invalid or expired session token' });
  }

  const users = readJSON(USERS_FILE);
  const user = users.find(u => u.id === userId);
  if (!user) {
    return res.status(403).json({ error: 'User session invalid' });
  }

  req.userId = userId;
  req.username = user.username;
  next();
}

// ─── Gemini AI Setup ──────────────────────────────────────────────────
let genAI = null;
let model = null;

function initGemini(apiKey) {
  try {
    genAI = new GoogleGenerativeAI(apiKey);
    model = genAI.getGenerativeModel({ model: 'gemini-2.0-flash' });
    return true;
  } catch (e) {
    console.error('Failed to initialize Gemini:', e.message);
    return false;
  }
}

// Try initializing with env key
if (process.env.GEMINI_API_KEY && process.env.GEMINI_API_KEY !== 'your_gemini_api_key_here') {
  initGemini(process.env.GEMINI_API_KEY);
  console.log('✅ Gemini AI initialized from .env');
} else {
  console.log('⚠️  No Gemini API key in .env — AI features will use fallback mode');
}

// ─── System Prompt for AI Wellness Advisor ────────────────────────────
const WELLNESS_SYSTEM_PROMPT = `You are MindBuddy, a compassionate and knowledgeable mental wellness coach specifically designed for students preparing for competitive exams in India (NEET, JEE, CUET, CAT, GATE, UPSC, and board exams).

Your role:
- Provide empathetic, evidence-based mental wellness advice
- Understand the unique pressures of Indian competitive exam culture
- Offer practical coping strategies for exam anxiety, burnout, self-doubt, and academic stress
- Suggest study-break activities, breathing techniques, and mindfulness exercises
- Recognize when professional help should be recommended
- Always be encouraging without being dismissive of struggles
- Keep responses concise (2-4 paragraphs max) and actionable

Important guidelines:
- Never provide medical diagnoses or prescribe medication
- Always validate the student's feelings before offering advice
- Use warm, friendly language — you're a supportive friend, not a clinical therapist
- Reference specific exam contexts when relevant (e.g., "JEE preparation can be grueling...")
- Include at least one concrete, actionable tip in every response
- If mood data is provided, reference specific patterns you notice

Respond in a warm, conversational tone. Use occasional emojis sparingly for friendliness.`;

// ─── API Routes ───────────────────────────────────────────────────────

// ─── Auth Endpoints ───────────────────────────────────────────────────
app.post('/api/auth/signup', (req, res) => {
  const { username, password } = req.body;
  if (!username || username.trim() === '') {
    return res.status(400).json({ error: 'Username is required' });
  }
  if (!password || password.length < 6) {
    return res.status(400).json({ error: 'Password must be at least 6 characters long' });
  }

  const users = readJSON(USERS_FILE);
  const nameLower = username.trim().toLowerCase();
  if (users.some(u => u.username.toLowerCase() === nameLower)) {
    return res.status(400).json({ error: 'Username is already taken' });
  }

  const salt = generateSalt();
  const passwordHash = hashPassword(password, salt);
  const userId = uuidv4();

  const newUser = {
    id: userId,
    username: username.trim(),
    salt,
    passwordHash,
    createdAt: new Date().toISOString()
  };

  users.push(newUser);
  writeJSON(USERS_FILE, users);

  const token = generateToken(userId);
  res.status(201).json({
    message: 'User registered successfully',
    token,
    username: newUser.username
  });
});

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const users = readJSON(USERS_FILE);
  const nameLower = username.trim().toLowerCase();
  const user = users.find(u => u.username.toLowerCase() === nameLower);

  if (!user) {
    return res.status(400).json({ error: 'Invalid username or password' });
  }

  const expectedHash = hashPassword(password, user.salt);
  if (expectedHash !== user.passwordHash) {
    return res.status(400).json({ error: 'Invalid username or password' });
  }

  const token = generateToken(user.id);
  res.json({
    message: 'Logged in successfully',
    token,
    username: user.username
  });
});

// Check API configuration
app.get('/api/config', authenticateToken, (req, res) => {
  res.json({
    geminiConfigured: model !== null,
    serverTime: new Date().toISOString()
  });
});

// Set API key dynamically
app.post('/api/config/key', authenticateToken, (req, res) => {
  const { apiKey } = req.body;
  if (!apiKey || apiKey.trim() === '') {
    return res.status(400).json({ error: 'API key is required' });
  }
  const success = initGemini(apiKey.trim());
  if (success) {
    res.json({ message: 'Gemini API key configured successfully', geminiConfigured: true });
  } else {
    res.status(500).json({ error: 'Failed to initialize Gemini with provided key' });
  }
});

// ─── Profile Endpoints ────────────────────────────────────────────────
app.get('/api/profile', authenticateToken, (req, res) => {
  const profileFile = getUserFilePath(req.userId, 'profile.json');
  let profile = readJSON(profileFile);
  if (Array.isArray(profile)) {
    profile = {};
  }
  if (!profile.onboarded) {
    profile.onboarded = false;
  }
  res.json(profile);
});

app.post('/api/profile', authenticateToken, (req, res) => {
  const { name, examContext, studyHours, stressors, wellnessGoals, emergencyName, emergencyPhone, milestones } = req.body;
  if (!name || name.trim() === '') {
    return res.status(400).json({ error: 'Name is required' });
  }
  const profile = {
    name: name.trim(),
    examContext: examContext || 'General',
    studyHours: studyHours || 'General',
    stressors: Array.isArray(stressors) ? stressors : [],
    wellnessGoals: Array.isArray(wellnessGoals) ? wellnessGoals : [],
    emergencyName: emergencyName ? emergencyName.trim() : '',
    emergencyPhone: emergencyPhone ? emergencyPhone.trim() : '',
    milestones: Array.isArray(milestones) ? milestones : [],
    onboarded: true,
    updatedAt: new Date().toISOString()
  };
  const profileFile = getUserFilePath(req.userId, 'profile.json');
  writeJSON(profileFile, profile);
  res.json(profile);
});

// ─── Mood Endpoints ──────────────────────────────────────────────────

// Log a mood entry
app.post('/api/mood', authenticateToken, (req, res) => {
  const { level, emotions, note, examContext } = req.body;

  // Validation
  if (!level || level < 1 || level > 5) {
    return res.status(400).json({ error: 'Mood level must be between 1 and 5' });
  }
  if (!emotions || !Array.isArray(emotions) || emotions.length === 0) {
    return res.status(400).json({ error: 'At least one emotion tag is required' });
  }

  const moodsFile = getUserFilePath(req.userId, 'moods.json');
  const moods = readJSON(moodsFile);
  const entry = {
    id: uuidv4(),
    level: Number(level),
    emotions,
    note: note || '',
    examContext: examContext || 'General',
    timestamp: new Date().toISOString()
  };

  moods.unshift(entry);
  writeJSON(moodsFile, moods);

  res.status(201).json(entry);
});

// Get mood history
app.get('/api/mood', authenticateToken, (req, res) => {
  const moodsFile = getUserFilePath(req.userId, 'moods.json');
  const moods = readJSON(moodsFile);
  const { days } = req.query;

  if (days) {
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - Number(days));
    const filtered = moods.filter(m => new Date(m.timestamp) >= cutoff);
    return res.json(filtered);
  }

  res.json(moods);
});

// Delete a mood entry
app.delete('/api/mood/:id', authenticateToken, (req, res) => {
  const moodsFile = getUserFilePath(req.userId, 'moods.json');
  let moods = readJSON(moodsFile);
  const before = moods.length;
  moods = moods.filter(m => m.id !== req.params.id);
  if (moods.length === before) {
    return res.status(404).json({ error: 'Mood entry not found' });
  }
  writeJSON(moodsFile, moods);
  res.json({ message: 'Deleted' });
});

// ─── Journal Endpoints ───────────────────────────────────────────────

// Save journal entry
app.post('/api/journal', authenticateToken, (req, res) => {
  const { title, content, prompt } = req.body;

  if (!content || content.trim().length === 0) {
    return res.status(400).json({ error: 'Journal content cannot be empty' });
  }
  if (content.length > 5000) {
    return res.status(400).json({ error: 'Journal content exceeds 5000 character limit' });
  }

  const journalsFile = getUserFilePath(req.userId, 'journals.json');
  const journals = readJSON(journalsFile);
  const entry = {
    id: uuidv4(),
    title: title || 'Untitled Entry',
    content: content.trim(),
    prompt: prompt || null,
    timestamp: new Date().toISOString()
  };

  journals.unshift(entry);
  writeJSON(journalsFile, journals);

  res.status(201).json(entry);
});

// Get journal entries
app.get('/api/journal', authenticateToken, (req, res) => {
  const journalsFile = getUserFilePath(req.userId, 'journals.json');
  const journals = readJSON(journalsFile);
  res.json(journals);
});

// Delete journal entry
app.delete('/api/journal/:id', authenticateToken, (req, res) => {
  const journalsFile = getUserFilePath(req.userId, 'journals.json');
  let journals = readJSON(journalsFile);
  const before = journals.length;
  journals = journals.filter(j => j.id !== req.params.id);
  if (journals.length === before) {
    return res.status(404).json({ error: 'Journal entry not found' });
  }
  writeJSON(journalsFile, journals);
  res.json({ message: 'Deleted' });
});

// ─── AI Wellness Advisor ─────────────────────────────────────────────

app.post('/api/wellness/advice', authenticateToken, async (req, res) => {
  const { message, moodHistory } = req.body;

  if (!message || message.trim().length === 0) {
    return res.status(400).json({ error: 'Message is required' });
  }

  // Build context from user profile
  let profileContext = '';
  let profile = {};
  try {
    const profileFile = getUserFilePath(req.userId, 'profile.json');
    profile = readJSON(profileFile);
    if (Array.isArray(profile)) profile = {};
    if (profile && profile.onboarded) {
      profileContext = `\n\nUSER PROFILE DETAILS:
- Student Name: ${profile.name}
- Preparing For: ${profile.examContext}
- Daily Study Commitment: ${profile.studyHours}
- Major Stressors: ${(profile.stressors || []).join(', ')}
- Wellness Goals: ${(profile.wellnessGoals || []).join(', ')}

IMPORTANT: Always refer to the student by their name, ${profile.name}, in your response and tailor your advice directly to their target exam (${profile.examContext}), specific stressors, and wellness goals. Make the advice feel personalized to them.`;
    }
  } catch (e) {
    console.error('Failed to parse user profile for advisor context:', e.message);
  }

  // Build context from recent moods
  let moodContext = '';
  if (moodHistory && moodHistory.length > 0) {
    const recent = moodHistory.slice(0, 7);
    const avgMood = (recent.reduce((sum, m) => sum + m.level, 0) / recent.length).toFixed(1);
    const allEmotions = recent.flatMap(m => m.emotions);
    const emotionFreq = {};
    allEmotions.forEach(e => { emotionFreq[e] = (emotionFreq[e] || 0) + 1; });
    const topEmotions = Object.entries(emotionFreq).sort((a, b) => b[1] - a[1]).slice(0, 5);

    moodContext = `\n\nRECENT MOOD DATA (last ${recent.length} entries):
- Average mood level: ${avgMood}/5
- Most frequent emotions: ${topEmotions.map(([e, c]) => `${e} (${c}x)`).join(', ')}
- Latest mood: ${recent[0].level}/5 with emotions: ${recent[0].emotions.join(', ')}
- Exam context: ${recent[0].examContext || 'General'}`;
  }

  const fullPrompt = `${WELLNESS_SYSTEM_PROMPT}${profileContext}${moodContext}\n\nStudent's message: ${message}`;

  // Try Gemini first
  if (model) {
    try {
      const result = await model.generateContent(fullPrompt);
      const response = result.response.text();
      return res.json({ advice: response, source: 'gemini' });
    } catch (e) {
      console.error('Gemini error:', e.message);
    }
  }

  // Fallback response
  const fallbackAdvice = generateFallbackAdvice(message, moodHistory, profile);
  res.json({ advice: fallbackAdvice, source: 'fallback' });
});

function generateFallbackAdvice(message, moodHistory, profile) {
  const msgLower = message.toLowerCase();
  const userName = (profile && profile.onboarded) ? profile.name : '';
  const greeting = userName ? `I hear you, ${userName} — ` : 'I hear you — ';
  const greetingAnxiety = userName ? `Hi ${userName}, exam anxiety is incredibly common, ` : 'Exam anxiety is incredibly common, ';
  const greetingMotivation = userName ? `Hi ${userName}, feeling unmotivated is a signal, not a flaw. ` : 'Feeling unmotivated is a signal, not a flaw. ';
  
  const responses = {
    stress: `${greeting}exam stress can feel overwhelming, especially when it seems like everything depends on one test. 💙\n\nHere's what might help right now:\n\n**🌊 The 5-4-3-2-1 Grounding Technique**: Look around and name 5 things you see, 4 you can touch, 3 you hear, 2 you smell, 1 you taste. This instantly pulls you out of anxious spirals.\n\n**📋 Break it down**: Instead of thinking "I need to cover the entire syllabus," pick just ONE topic for the next 45 minutes. Small wins build momentum.\n\nRemember: You're not defined by a single exam. You're doing your best, and that matters. 🌟`,
    
    anxiety: `${greetingAnxiety}and it actually shows that you care about doing well — which is a good thing! 🌸\n\n**Try this right now:**\n1. Place your hand on your chest\n2. Breathe in for 4 counts, hold for 4, exhale for 6\n3. Repeat 3 times\n\nThis activates your parasympathetic nervous system and physically calms you down.\n\n**Pro tip**: If anxiety hits during study, try the "worst case / best case / most likely case" exercise. Write down all three scenarios — you'll usually find the most likely case is quite manageable. 💪`,
    
    burnout: `Burnout is your mind's way of saying it needs rest — and rest is NOT laziness. It's essential maintenance${userName ? `, ${userName}` : ''}! 🔋\n\n**Recovery plan:**\n- Take a genuine break today (at least 2 hours of zero studying)\n- Do something that brings you joy — walk, music, cooking, chatting with friends\n- Tonight, aim for 7-8 hours of sleep (it improves memory consolidation!)\n\nMany toppers will tell you: strategic rest improved their scores more than grinding through exhaustion. Quality over quantity, always. ✨`,
    
    motivation: `${greetingMotivation}Let's work with it, not against it. 🎯\n\n**Quick motivation reboot:**\n1. **Revisit your WHY**: Write down in one sentence why you started preparing. Put it where you can see it.\n2. **Lower the bar today**: Instead of 8 hours, commit to just 25 minutes of focused study (Pomodoro technique). Often, starting is the hardest part.\n3. **Celebrate micro-wins**: Finished a chapter? Solved 5 problems? That counts!\n\nYou haven't come this far to only come this far. 🚀`,
    
    default: `Thank you for sharing what you're going through${userName ? `, ${userName}` : ''}. It takes courage to talk about how you're feeling. 💙\n\nHere are some things that might help:\n\n**🧘 Mindful Check-in**: Take 2 minutes to sit quietly and ask yourself: "What do I need most right now?" — Is it rest? Connection? A small win? Honor that need.\n\n**📝 Brain Dump**: Write down everything swirling in your mind for 5 minutes. Getting it out of your head and onto paper reduces mental load dramatically.\n\n**🤝 Reach Out**: Talk to someone you trust — a friend, family member, or counselor. You don't have to navigate this alone.\n\nRemember: Your worth is not determined by any exam score. You matter, period. 🌟`
  };

  if (msgLower.includes('stress') || msgLower.includes('pressure') || msgLower.includes('overwhelm')) return responses.stress;
  if (msgLower.includes('anxi') || msgLower.includes('nervous') || msgLower.includes('worry') || msgLower.includes('scared')) return responses.anxiety;
  if (msgLower.includes('burnout') || msgLower.includes('tired') || msgLower.includes('exhausted') || msgLower.includes('burnt')) return responses.burnout;
  if (msgLower.includes('motivat') || msgLower.includes('lazy') || msgLower.includes('give up') || msgLower.includes('quit')) return responses.motivation;
  return responses.default;
}

// ─── Breathing Exercises ─────────────────────────────────────────────

app.get('/api/wellness/breathing', authenticateToken, (req, res) => {
  const exercises = [
    {
      id: 'box',
      name: 'Box Breathing',
      description: 'Used by Navy SEALs for instant calm. Equal counts for inhale, hold, exhale, hold.',
      steps: [
        { action: 'Inhale', duration: 4 },
        { action: 'Hold', duration: 4 },
        { action: 'Exhale', duration: 4 },
        { action: 'Hold', duration: 4 }
      ],
      cycles: 4,
      color: '#2dd4bf'
    },
    {
      id: '478',
      name: '4-7-8 Technique',
      description: 'Dr. Andrew Weil\'s relaxation method. Slows heart rate and promotes sleepiness.',
      steps: [
        { action: 'Inhale', duration: 4 },
        { action: 'Hold', duration: 7 },
        { action: 'Exhale', duration: 8 }
      ],
      cycles: 4,
      color: '#a78bfa'
    },
    {
      id: 'deep',
      name: 'Deep Calm',
      description: 'Extended exhale activates your parasympathetic nervous system for deep relaxation.',
      steps: [
        { action: 'Inhale', duration: 5 },
        { action: 'Hold', duration: 2 },
        { action: 'Exhale', duration: 8 }
      ],
      cycles: 5,
      color: '#38bdf8'
    }
  ];
  res.json(exercises);
});

// ─── Analytics / Stats ───────────────────────────────────────────────

app.get('/api/stats', authenticateToken, (req, res) => {
  const moodsFile = getUserFilePath(req.userId, 'moods.json');
  const moods = readJSON(moodsFile);
  
  if (moods.length === 0) {
    return res.json({
      totalEntries: 0,
      averageMood: 0,
      moodDistribution: {},
      topEmotions: [],
      weeklyTrend: [],
      streakDays: 0
    });
  }

  // Average mood
  const avgMood = (moods.reduce((s, m) => s + m.level, 0) / moods.length).toFixed(2);

  // Mood distribution
  const distribution = { 1: 0, 2: 0, 3: 0, 4: 0, 5: 0 };
  moods.forEach(m => { distribution[m.level] = (distribution[m.level] || 0) + 1; });

  // Top emotions
  const emotionCount = {};
  moods.forEach(m => {
    m.emotions.forEach(e => { emotionCount[e] = (emotionCount[e] || 0) + 1; });
  });
  const topEmotions = Object.entries(emotionCount)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 8)
    .map(([emotion, count]) => ({ emotion, count }));

  // Weekly trend (last 7 days)
  const weeklyTrend = [];
  for (let i = 6; i >= 0; i--) {
    const date = new Date();
    date.setDate(date.getDate() - i);
    const dayStr = date.toISOString().split('T')[0];
    const dayMoods = moods.filter(m => m.timestamp.startsWith(dayStr));
    const avg = dayMoods.length > 0
      ? (dayMoods.reduce((s, m) => s + m.level, 0) / dayMoods.length).toFixed(1)
      : null;
    weeklyTrend.push({
      date: dayStr,
      label: date.toLocaleDateString('en-US', { weekday: 'short' }),
      average: avg ? Number(avg) : null,
      count: dayMoods.length
    });
  }

  // Streak calculation
  let streakDays = 0;
  for (let i = 0; i < 365; i++) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    const dayStr = d.toISOString().split('T')[0];
    if (moods.some(m => m.timestamp.startsWith(dayStr))) {
      streakDays++;
    } else {
      break;
    }
  }

  // Exam context distribution
  const examDist = {};
  moods.forEach(m => {
    const ctx = m.examContext || 'General';
    examDist[ctx] = (examDist[ctx] || 0) + 1;
  });

  res.json({
    totalEntries: moods.length,
    averageMood: Number(avgMood),
    moodDistribution: distribution,
    topEmotions,
    weeklyTrend,
    streakDays,
    examDistribution: examDist
  });
});

// ─── Reflection Prompts ──────────────────────────────────────────────

app.get('/api/journal/prompts', authenticateToken, (req, res) => {
  const prompts = [
    "What's one thing that went well in your studies today?",
    "What exam-related thought has been occupying your mind the most?",
    "Describe a moment today when you felt proud of yourself.",
    "What would you tell a friend who's feeling the way you are right now?",
    "What's one small thing you can do tomorrow to feel more prepared?",
    "Write about a time you overcame a challenge — how did you do it?",
    "What are three things you're grateful for today, no matter how small?",
    "If your stress could talk, what would it say? What would you say back?",
    "What does your ideal day look like during exam season?",
    "Write a letter to your future self after the exams are over.",
    "What boundaries do you need to set to protect your mental health?",
    "Describe your happy place in detail. What does it look, feel, and sound like?"
  ];

  // Return a random prompt
  const randomPrompt = prompts[Math.floor(Math.random() * prompts.length)];
  res.json({ prompt: randomPrompt, allPrompts: prompts });
});

// ─── Start Server ────────────────────────────────────────────────────

app.listen(PORT, () => {
  console.log(`\n🧠 Mental Wellness Tracker Server`);
  console.log(`   Running on http://localhost:${PORT}`);
  console.log(`   Gemini AI: ${model ? '✅ Connected' : '⚠️  Fallback mode'}`);
  console.log(`   Data dir:  ${DATA_DIR}\n`);
});
