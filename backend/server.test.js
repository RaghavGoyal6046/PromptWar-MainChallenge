/**
 * MindBuddy Backend API — Comprehensive Test Suite
 * Uses Node.js built-in test runner (no external dependencies)
 * Tests: Auth, Profile, Mood, Journal, Stats, Breathing, AI Advisor, Security
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('path');
const fs = require('fs');
const app = require('./server');

let server;
let port;
let baseUrl;

// ─── Test Lifecycle ────────────────────────────────────────────────────────────
test.before(() => {
  server = app.listen(0);
  port = server.address().port;
  baseUrl = `http://localhost:${port}`;
  console.log(`\n🧪 Test server running on port ${port}`);
});

test.after(() => {
  server.close();
  // Clean up all test users from users.json and data directories
  try {
    const usersFile = path.join(__dirname, 'data', 'users.json');
    if (fs.existsSync(usersFile)) {
      let users = JSON.parse(fs.readFileSync(usersFile, 'utf8'));
      const testUsers = users.filter(u => u.username.startsWith('testrun_'));
      testUsers.forEach(u => {
        const userDir = path.join(__dirname, 'data', 'users', u.id);
        if (fs.existsSync(userDir)) fs.rmSync(userDir, { recursive: true, force: true });
      });
      users = users.filter(u => !u.username.startsWith('testrun_'));
      fs.writeFileSync(usersFile, JSON.stringify(users, null, 2));
    }
  } catch (e) {
    console.error('Cleanup error:', e.message);
  }
  console.log('\n✅ Test cleanup complete');
});

// ─── Helper: Create a fresh test user and return { token, username } ────────────
async function createTestUser(suffix) {
  const username = `testrun_${suffix}_${Date.now()}`;
  const res = await fetch(`${baseUrl}/api/auth/signup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password: 'TestPass123' })
  });
  const data = await res.json();
  return { token: data.token, username: data.username };
}

// ─── Helper: Authenticated fetch ────────────────────────────────────────────────
async function af(url, token, options = {}) {
  return fetch(`${baseUrl}${url}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`,
      ...options.headers
    }
  });
}

// ══════════════════════════════════════════════════════════════════════════════
// 1. AUTHENTICATION TESTS
// ══════════════════════════════════════════════════════════════════════════════
test('1. Authentication — Signup', async (t) => {
  await t.test('1a. Rejects empty username', async () => {
    const res = await fetch(`${baseUrl}/api/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: '', password: 'password123' })
    });
    assert.equal(res.status, 400);
  });

  await t.test('1b. Rejects password shorter than 6 chars', async () => {
    const res = await fetch(`${baseUrl}/api/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'testrun_shortpw', password: 'abc' })
    });
    assert.equal(res.status, 400);
    const data = await res.json();
    assert.ok(data.error.includes('Password'));
  });

  await t.test('1c. Creates a new user successfully', async () => {
    const username = `testrun_signup_${Date.now()}`;
    const res = await fetch(`${baseUrl}/api/auth/signup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password: 'SecurePass1' })
    });
    assert.equal(res.status, 201);
    const data = await res.json();
    assert.ok(data.token, 'Token should be returned');
    assert.equal(data.username, username);
  });

  await t.test('1d. Prevents duplicate usernames (case-insensitive)', async () => {
    const username = `testrun_dup_${Date.now()}`;
    await fetch(`${baseUrl}/api/auth/signup`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password: 'password123' })
    });
    // Try with UPPERCASE version
    const res2 = await fetch(`${baseUrl}/api/auth/signup`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: username.toUpperCase(), password: 'password123' })
    });
    assert.equal(res2.status, 400);
    const data = await res2.json();
    assert.ok(data.error.includes('taken'));
  });
});

test('2. Authentication — Login', async (t) => {
  const { username } = await createTestUser('login');

  await t.test('2a. Logs in with correct credentials', async () => {
    const res = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password: 'TestPass123' })
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(data.token);
    assert.equal(data.username, username);
  });

  await t.test('2b. Rejects wrong password', async () => {
    const res = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password: 'WrongPassword!' })
    });
    assert.equal(res.status, 400);
  });

  await t.test('2c. Rejects non-existent username', async () => {
    const res = await fetch(`${baseUrl}/api/auth/login`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username: 'ghost_user_xyz', password: 'any_pass' })
    });
    assert.equal(res.status, 400);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// 2. SECURITY / MIDDLEWARE TESTS
// ══════════════════════════════════════════════════════════════════════════════
test('3. Security — Authentication Middleware', async (t) => {
  await t.test('3a. Rejects request without token', async () => {
    const res = await fetch(`${baseUrl}/api/profile`);
    assert.equal(res.status, 401);
  });

  await t.test('3b. Rejects request with invalid token', async () => {
    const res = await fetch(`${baseUrl}/api/profile`, {
      headers: { 'Authorization': 'Bearer this_is_not_valid_base64_token' }
    });
    assert.equal(res.status, 403);
  });

  await t.test('3c. Rejects malformed Authorization header', async () => {
    const res = await fetch(`${baseUrl}/api/mood`, {
      headers: { 'Authorization': 'NotBearer sometoken' }
    });
    assert.equal(res.status, 401);
  });

  await t.test('3d. Data is isolated between users', async () => {
    const userA = await createTestUser('isolation_a');
    const userB = await createTestUser('isolation_b');

    // User A logs a mood
    await af('/api/mood', userA.token, {
      method: 'POST',
      body: JSON.stringify({ level: 5, emotions: ['Hopeful'], note: 'Top secret mood', examContext: 'JEE' })
    });

    // User B should not see User A's mood
    const bRes = await af('/api/mood', userB.token);
    const bMoods = await bRes.json();
    assert.equal(bMoods.length, 0, 'User B should see no moods from User A');
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// 3. PROFILE TESTS
// ══════════════════════════════════════════════════════════════════════════════
test('4. Profile API', async (t) => {
  const { token } = await createTestUser('profile');

  await t.test('4a. Initially returns non-onboarded profile', async () => {
    const res = await af('/api/profile', token);
    assert.equal(res.status, 200);
    const profile = await res.json();
    assert.equal(profile.onboarded, false);
  });

  await t.test('4b. Saves a full profile successfully', async () => {
    const profileData = {
      name: 'Priya Sharma', examContext: 'NEET', studyHours: '8-10 Hours',
      stressors: ['Mock Test Failure', 'Peer Comparison'],
      wellnessGoals: ['Reduce Exam Anxiety'],
      emergencyName: 'Maa', emergencyPhone: '9876543210'
    };
    const res = await af('/api/profile', token, {
      method: 'POST', body: JSON.stringify(profileData)
    });
    assert.equal(res.status, 200);
    const profile = await res.json();
    assert.equal(profile.name, 'Priya Sharma');
    assert.equal(profile.examContext, 'NEET');
    assert.equal(profile.onboarded, true);
    assert.deepEqual(profile.stressors, ['Mock Test Failure', 'Peer Comparison']);
  });

  await t.test('4c. Rejects profile with missing name', async () => {
    const res = await af('/api/profile', token, {
      method: 'POST', body: JSON.stringify({ name: '', examContext: 'JEE' })
    });
    assert.equal(res.status, 400);
  });

  await t.test('4d. Updates an existing profile', async () => {
    const res = await af('/api/profile', token, {
      method: 'POST',
      body: JSON.stringify({
        name: 'Priya S.', examContext: 'NEET',
        studyHours: '10+ Hours', stressors: [], wellnessGoals: []
      })
    });
    assert.equal(res.status, 200);
    const p = await res.json();
    assert.equal(p.name, 'Priya S.');
    assert.equal(p.studyHours, '10+ Hours');
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// 4. MOOD TRACKING TESTS
// ══════════════════════════════════════════════════════════════════════════════
test('5. Mood Tracking API', async (t) => {
  const { token } = await createTestUser('mood');
  let moodId1, moodId2;

  await t.test('5a. Rejects mood with invalid level (out of range)', async () => {
    const res = await af('/api/mood', token, {
      method: 'POST',
      body: JSON.stringify({ level: 7, emotions: ['Calm'], examContext: 'General' })
    });
    assert.equal(res.status, 400);
  });

  await t.test('5b. Rejects mood with no emotions', async () => {
    const res = await af('/api/mood', token, {
      method: 'POST',
      body: JSON.stringify({ level: 3, emotions: [], examContext: 'General' })
    });
    assert.equal(res.status, 400);
  });

  await t.test('5c. Logs mood at level 1 (lowest)', async () => {
    const res = await af('/api/mood', token, {
      method: 'POST',
      body: JSON.stringify({ level: 1, emotions: ['Burnout', 'Stressed'], note: 'Rough day', examContext: 'NEET' })
    });
    assert.equal(res.status, 201);
    const mood = await res.json();
    assert.equal(mood.level, 1);
    assert.ok(mood.id);
    moodId1 = mood.id;
  });

  await t.test('5d. Logs mood at level 5 (highest)', async () => {
    const res = await af('/api/mood', token, {
      method: 'POST',
      body: JSON.stringify({ level: 5, emotions: ['Hopeful', 'Calm'], note: 'Great revision', examContext: 'JEE' })
    });
    assert.equal(res.status, 201);
    const mood = await res.json();
    assert.equal(mood.level, 5);
    moodId2 = mood.id;
  });

  await t.test('5e. Retrieves full mood history', async () => {
    const res = await af('/api/mood', token);
    assert.equal(res.status, 200);
    const moods = await res.json();
    assert.equal(moods.length, 2);
  });

  await t.test('5f. Mood has required fields (id, timestamp, level, emotions)', async () => {
    const res = await af('/api/mood', token);
    const moods = await res.json();
    const mood = moods[0];
    assert.ok(mood.id);
    assert.ok(mood.timestamp);
    assert.ok(mood.level);
    assert.ok(Array.isArray(mood.emotions));
  });

  await t.test('5g. Returns 404 when deleting non-existent mood', async () => {
    const res = await af('/api/mood/non_existent_id_xyz', token, { method: 'DELETE' });
    assert.equal(res.status, 404);
  });

  await t.test('5h. Deletes an existing mood successfully', async () => {
    const res = await af(`/api/mood/${moodId1}`, token, { method: 'DELETE' });
    assert.equal(res.status, 200);

    const checkRes = await af('/api/mood', token);
    const moods = await checkRes.json();
    assert.equal(moods.length, 1);
    assert.equal(moods[0].id, moodId2);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// 5. JOURNAL TESTS
// ══════════════════════════════════════════════════════════════════════════════
test('6. Journal API', async (t) => {
  const { token } = await createTestUser('journal');
  let journalId;

  await t.test('6a. Rejects empty journal content', async () => {
    const res = await af('/api/journal', token, {
      method: 'POST',
      body: JSON.stringify({ title: 'Empty Entry', content: '   ' })
    });
    assert.equal(res.status, 400);
  });

  await t.test('6b. Rejects content exceeding 5000 chars', async () => {
    const res = await af('/api/journal', token, {
      method: 'POST',
      body: JSON.stringify({ title: 'Long', content: 'x'.repeat(5001) })
    });
    assert.equal(res.status, 400);
  });

  await t.test('6c. Saves a valid journal entry', async () => {
    const res = await af('/api/journal', token, {
      method: 'POST',
      body: JSON.stringify({
        title: 'My First Entry',
        content: 'Today I revised organic chemistry and felt better than yesterday.',
        prompt: "What's one thing you did well today?"
      })
    });
    assert.equal(res.status, 201);
    const entry = await res.json();
    assert.equal(entry.title, 'My First Entry');
    assert.ok(entry.id);
    journalId = entry.id;
  });

  await t.test('6d. Uses default title if none provided', async () => {
    const res = await af('/api/journal', token, {
      method: 'POST',
      body: JSON.stringify({ content: 'Untitled content here' })
    });
    const entry = await res.json();
    assert.equal(entry.title, 'Untitled Entry');
  });

  await t.test('6e. Retrieves journal entries', async () => {
    const res = await af('/api/journal', token);
    assert.equal(res.status, 200);
    const entries = await res.json();
    assert.ok(entries.length >= 2);
    // Most recent entry should be first
    assert.ok(new Date(entries[0].timestamp) >= new Date(entries[1].timestamp));
  });

  await t.test('6f. Returns a reflection prompt', async () => {
    const res = await af('/api/journal/prompts', token);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(data.prompt);
    assert.ok(data.prompt.length > 10);
    assert.ok(Array.isArray(data.allPrompts));
    assert.ok(data.allPrompts.length > 5);
  });

  await t.test('6g. Deletes a journal entry successfully', async () => {
    const res = await af(`/api/journal/${journalId}`, token, { method: 'DELETE' });
    assert.equal(res.status, 200);
  });

  await t.test('6h. Returns 404 for non-existent journal entry deletion', async () => {
    const res = await af('/api/journal/non_existent_id', token, { method: 'DELETE' });
    assert.equal(res.status, 404);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// 6. ANALYTICS / STATS TESTS
// ══════════════════════════════════════════════════════════════════════════════
test('7. Analytics & Stats API', async (t) => {
  const { token } = await createTestUser('stats');

  await t.test('7a. Returns zero-stats for new user', async () => {
    const res = await af('/api/stats', token);
    assert.equal(res.status, 200);
    const stats = await res.json();
    assert.equal(stats.totalEntries, 0);
    assert.equal(stats.streakDays, 0);
  });

  await t.test('7b. Calculates correct average after logging moods', async () => {
    // Log 3 moods: 2, 4, 3 → avg = 3
    const levels = [2, 4, 3];
    for (const level of levels) {
      await af('/api/mood', token, {
        method: 'POST',
        body: JSON.stringify({ level, emotions: ['Calm'], examContext: 'General' })
      });
    }
    const res = await af('/api/stats', token);
    const stats = await res.json();
    assert.equal(stats.totalEntries, 3);
    assert.ok(parseFloat(stats.averageMood) === 3, `Expected avg 3, got ${stats.averageMood}`);
  });

  await t.test('7c. Returns a weekly trend array with 7 items', async () => {
    const res = await af('/api/stats', token);
    const stats = await res.json();
    assert.ok(Array.isArray(stats.weeklyTrend));
    assert.equal(stats.weeklyTrend.length, 7);
  });

  await t.test('7d. Returns top emotions array', async () => {
    const res = await af('/api/stats', token);
    const stats = await res.json();
    assert.ok(Array.isArray(stats.topEmotions));
    if (stats.topEmotions.length > 0) {
      assert.ok(stats.topEmotions[0].emotion);
      assert.ok(stats.topEmotions[0].count > 0);
    }
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// 7. BREATHING EXERCISES TESTS
// ══════════════════════════════════════════════════════════════════════════════
test('8. Breathing Exercises API', async (t) => {
  const { token } = await createTestUser('breathing');

  await t.test('8a. Returns a list of breathing exercises', async () => {
    const res = await af('/api/wellness/breathing', token);
    assert.equal(res.status, 200);
    const exercises = await res.json();
    assert.ok(Array.isArray(exercises));
    assert.ok(exercises.length >= 3);
  });

  await t.test('8b. Each exercise has required fields', async () => {
    const res = await af('/api/wellness/breathing', token);
    const exercises = await res.json();
    for (const ex of exercises) {
      assert.ok(ex.id, 'Exercise must have id');
      assert.ok(ex.name, 'Exercise must have name');
      assert.ok(Array.isArray(ex.steps), 'Exercise must have steps');
      assert.ok(ex.cycles > 0, 'Exercise must have positive cycles');
    }
  });

  await t.test('8c. Each step has action and duration', async () => {
    const res = await af('/api/wellness/breathing', token);
    const exercises = await res.json();
    for (const ex of exercises) {
      for (const step of ex.steps) {
        assert.ok(['Inhale', 'Hold', 'Exhale'].includes(step.action), `Unknown action: ${step.action}`);
        assert.ok(step.duration > 0);
      }
    }
  });

  await t.test('8d. Box Breathing exercise exists', async () => {
    const res = await af('/api/wellness/breathing', token);
    const exercises = await res.json();
    const box = exercises.find(e => e.id === 'box');
    assert.ok(box, 'Box Breathing should exist');
    assert.equal(box.steps.length, 4);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// 8. AI WELLNESS ADVISOR TESTS
// ══════════════════════════════════════════════════════════════════════════════
test('9. AI Wellness Advisor API (Fallback Mode)', async (t) => {
  const { token } = await createTestUser('advisor');

  await t.test('9a. Rejects empty message', async () => {
    const res = await af('/api/wellness/advice', token, {
      method: 'POST',
      body: JSON.stringify({ message: '   ', moodHistory: [] })
    });
    assert.equal(res.status, 400);
  });

  await t.test('9b. Returns advice for stress message', async () => {
    const res = await af('/api/wellness/advice', token, {
      method: 'POST',
      body: JSON.stringify({ message: 'I am feeling so stressed about my exam', moodHistory: [] })
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(data.advice, 'Advice should be returned');
    assert.ok(data.advice.length > 20);
    assert.ok(data.source);
  });

  await t.test('9c. Returns advice for burnout message', async () => {
    const res = await af('/api/wellness/advice', token, {
      method: 'POST',
      body: JSON.stringify({ message: 'I am completely burnt out and exhausted', moodHistory: [] })
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(data.advice.length > 20);
  });

  await t.test('9d. Accepts mood history context', async () => {
    const moodHistory = [
      { level: 2, emotions: ['Stressed'], examContext: 'NEET', timestamp: new Date().toISOString() },
      { level: 1, emotions: ['Burnout'], examContext: 'NEET', timestamp: new Date().toISOString() }
    ];
    const res = await af('/api/wellness/advice', token, {
      method: 'POST',
      body: JSON.stringify({ message: 'I need help managing my anxiety', moodHistory })
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(data.advice);
  });

  await t.test('9e. Returns default advice for generic message', async () => {
    const res = await af('/api/wellness/advice', token, {
      method: 'POST',
      body: JSON.stringify({ message: 'Just saying hi', moodHistory: [] })
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(data.advice);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// 9. CONFIG API TESTS
// ══════════════════════════════════════════════════════════════════════════════
test('10. Config API', async (t) => {
  const { token } = await createTestUser('config');

  await t.test('10a. Returns gemini config status', async () => {
    const res = await af('/api/config', token);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok('geminiConfigured' in data);
    assert.ok('serverTime' in data);
  });

  await t.test('10b. Rejects empty API key', async () => {
    const res = await af('/api/config/key', token, {
      method: 'POST',
      body: JSON.stringify({ apiKey: '' })
    });
    assert.equal(res.status, 400);
  });
});

// ══════════════════════════════════════════════════════════════════════════════
// 10. STATIC ASSETS TEST
// ══════════════════════════════════════════════════════════════════════════════
test('11. Static Assets Served', async (t) => {
  await t.test('11a. Serves index.html at root', async () => {
    const res = await fetch(`${baseUrl}/`);
    assert.equal(res.status, 200);
    const contentType = res.headers.get('content-type');
    assert.ok(contentType && contentType.includes('text/html'));
  });

  await t.test('11b. Serves index.css', async () => {
    const res = await fetch(`${baseUrl}/index.css`);
    assert.equal(res.status, 200);
    const contentType = res.headers.get('content-type');
    assert.ok(contentType && contentType.includes('css'));
  });
});
