import express from 'express';
import type { Request, Response, NextFunction } from 'express';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';
import crypto from 'crypto';
import dotenv from 'dotenv';
import { GoogleGenAI } from '@google/genai';
import { createServer as createViteServer } from 'vite';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const DATA_DIR = path.resolve(__dirname, 'data');
const ADMINS_FILE = path.resolve(DATA_DIR, 'admins.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// Security: PBKDF2 Password Hashing
function hashPassword(password: string, salt = crypto.randomBytes(16).toString('hex')): { hash: string; salt: string } {
  const hash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
  return { hash, salt };
}

function verifyPassword(password: string, hash: string, salt: string): boolean {
  try {
    const verifyHash = crypto.pbkdf2Sync(password, salt, 100000, 64, 'sha512').toString('hex');
    return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(verifyHash, 'hex'));
  } catch {
    return false;
  }
}

interface AdminRecord {
  id: string;
  name: string;
  email: string;
  role: 'admin';
  designation: string;
  department: string;
  phone: string;
  passwordHash: string;
  salt: string;
  registeredAt: string;
  isPrimary: boolean;
}

interface AdminsStore {
  admins: AdminRecord[];
}

// Initial Admin Credentials (securely hashed on initialization)
// Admin 1: ayushjaiswal272008@gmail.com
// Admin 2: Friend account (configurable by Ayush or with friend's chosen secure password)
function loadOrCreateAdmins(): AdminRecord[] {
  if (fs.existsSync(ADMINS_FILE)) {
    try {
      const data = JSON.parse(fs.readFileSync(ADMINS_FILE, 'utf-8')) as AdminsStore;
      if (Array.isArray(data.admins) && data.admins.length > 0) {
        // Guarantee Ayush Jaiswal has ayush007 active
        const ayush = data.admins.find((a) => a.email.toLowerCase() === 'ayushjaiswal272008@gmail.com');
        if (ayush && !verifyPassword('ayush007', ayush.passwordHash, ayush.salt)) {
          const creds = hashPassword('ayush007');
          ayush.passwordHash = creds.hash;
          ayush.salt = creds.salt;
          saveAdmins(data.admins);
        }
        return data.admins;
      }
    } catch (e) {
      console.error('Error reading admins file, recreating default:', e);
    }
  }

  // Generate initial secure credentials with PBKDF2 salt
  const admin1Creds = hashPassword('ayush007');
  const admin2Creds = hashPassword('FriendAdmin@2026!');

  const initialAdmins: AdminRecord[] = [
    {
      id: 'ADM-AYUSH-01',
      name: 'Ayush Jaiswal',
      email: 'ayushjaiswal272008@gmail.com',
      role: 'admin',
      designation: 'Chief System Administrator & ERP Head',
      department: 'Central ERP & Operations Directorate',
      phone: '+91 98710 22301',
      passwordHash: admin1Creds.hash,
      salt: admin1Creds.salt,
      registeredAt: new Date().toISOString(),
      isPrimary: true,
    },
    {
      id: 'ADM-FRIEND-02',
      name: 'Secondary Admin (Friend)',
      email: 'admin.friend@gniot.net.in',
      role: 'admin',
      designation: 'Co-Administrator (Facilities & ERP)',
      department: 'Campus Estate & Facilities',
      phone: '+91 98710 22302',
      passwordHash: admin2Creds.hash,
      salt: admin2Creds.salt,
      registeredAt: new Date().toISOString(),
      isPrimary: false,
    },
  ];

  fs.writeFileSync(ADMINS_FILE, JSON.stringify({ admins: initialAdmins }, null, 2));
  return initialAdmins;
}

function saveAdmins(admins: AdminRecord[]) {
  fs.writeFileSync(ADMINS_FILE, JSON.stringify({ admins }, null, 2));
}

// In-Memory Active Sessions Store
interface SessionData {
  token: string;
  adminId: string;
  email: string;
  name: string;
  designation: string;
  department: string;
  isPrimary: boolean;
  expiresAt: number;
}

const activeSessions = new Map<string, SessionData>();

function createSession(admin: AdminRecord): string {
  const token = crypto.randomBytes(32).toString('hex');
  const sessionData: SessionData = {
    token,
    adminId: admin.id,
    email: admin.email,
    name: admin.name,
    designation: admin.designation,
    department: admin.department,
    isPrimary: admin.isPrimary,
    expiresAt: Date.now() + 7 * 24 * 60 * 60 * 1000, // 7 days
  };
  activeSessions.set(token, sessionData);
  return token;
}

function getSessionFromToken(token?: string): SessionData | null {
  if (!token) return null;
  const session = activeSessions.get(token);
  if (!session) return null;
  if (Date.now() > session.expiresAt) {
    activeSessions.delete(token);
    return null;
  }
  return session;
}

// Gemini AI Client Setup
let genAi: GoogleGenAI | null = null;
if (process.env.GEMINI_API_KEY) {
  genAi = new GoogleGenAI({
    apiKey: process.env.GEMINI_API_KEY,
    httpOptions: {
      headers: {
        'User-Agent': 'aistudio-build',
      },
    },
  });
}

const GNIOT_SYSTEM_INSTRUCTION = `You are the official CampusFix AI Assistant for GNIOT Group of Institutions (Knowledge Park II, Greater Noida).
You assist students, faculty, staff, and administrators with campus maintenance, facility complaints, ERP grievance tracking, and hostel/lab repairs.

Key Campus Context:
- Institution: GNIOT Group of Institutions (Accredited NAAC A+, NBA, 25 Years of Excellence).
- Main Academic Blocks: APJ Abdul Kalam Block (Engineering & Technology), Tech Zone Block, Ramanujan Science Block, Management Block, Legal Studies Wing.
- Facilities: Central Chiller Plants & VRV AC, High-speed Campus Wi-Fi 6, 24/7 Substation & Power Backup, RO Water Purification Plants, Girls & Boys Hostels, Multi-cuisine Mess, Digital Classrooms.
- Ticketing Flow:
  1. Students/Staff file complaint with Block, Room Number, Category (Electrical, Plumbing, Wi-Fi, HVAC, Furniture, Cleaning, Security, Academic Labs).
  2. Ticket assigned unique Tracking ID (e.g., CMP-XXXX).
  3. Dispatch Lead assigns certified maintenance technician.
  4. Average turnaround: Urgent (2-4 hrs), High (12 hrs), Normal (24 hrs).
- System Developed and Engineered by: NEXUS.
- Chief System Administrator: Ayush Jaiswal (ayushjaiswal272008@gmail.com).

Tone: Friendly, professional, authoritative, and concise. Format with bullet points where helpful. If users ask about sensitive passwords, explain that administrator authentication is strictly protected and managed server-side.`;

// Express App Initialization
async function startServer() {
  const app = express();
  const PORT = Number(process.env.PORT) || 3000;

  app.use(express.json());

  // --- ADMIN AUTH & MANAGEMENT API ROUTES ---

  // Admin Login Endpoint
  app.post('/api/admin/login', (req: Request, res: Response): void => {
    const { identifier, email, password } = req.body;
    const inputEmail = (email || identifier || '').trim().toLowerCase();
    const inputPassword = (password || '').trim();

    if (!inputEmail || !inputPassword) {
      res.status(400).json({ success: false, error: 'Email/Identifier and password are required.' });
      return;
    }

    const admins = loadOrCreateAdmins();
    const targetAdmin = admins.find(
      (a) => a.email.toLowerCase() === inputEmail || a.id.toLowerCase() === inputEmail
    );

    if (!targetAdmin) {
      res.status(401).json({
        success: false,
        error: 'Access Denied: Only authorized administrators (Ayush Jaiswal or designated secondary admin) can access this system.',
      });
      return;
    }

    const isValid = verifyPassword(inputPassword, targetAdmin.passwordHash, targetAdmin.salt);
    if (!isValid) {
      res.status(401).json({ success: false, error: 'Invalid administrator credentials.' });
      return;
    }

    const token = createSession(targetAdmin);

    res.json({
      success: true,
      token,
      admin: {
        id: targetAdmin.id,
        name: targetAdmin.name,
        email: targetAdmin.email,
        role: targetAdmin.role,
        designation: targetAdmin.designation,
        department: targetAdmin.department,
        isPrimary: targetAdmin.isPrimary,
      },
    });
  });

  // Verify Admin Session Endpoint
  app.get('/api/admin/verify', (req: Request, res: Response): void => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : (req.query.token as string);
    const session = getSessionFromToken(token);

    if (!session) {
      res.status(401).json({ success: false, error: 'Invalid or expired administrator session.' });
      return;
    }

    res.json({ success: true, admin: session });
  });

  // Logout Endpoint
  app.post('/api/admin/logout', (req: Request, res: Response): void => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : req.body.token;
    if (token) {
      activeSessions.delete(token);
    }
    res.json({ success: true, message: 'Logged out successfully.' });
  });

  // List Authorized Administrators (Session required, hashes omitted)
  app.get('/api/admin/list', (req: Request, res: Response): void => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : (req.query.token as string);
    const session = getSessionFromToken(token);

    if (!session) {
      res.status(401).json({ success: false, error: 'Unauthorized.' });
      return;
    }

    const admins = loadOrCreateAdmins();
    const sanitized = admins.map((a) => ({
      id: a.id,
      name: a.name,
      email: a.email,
      role: a.role,
      designation: a.designation,
      department: a.department,
      phone: a.phone,
      registeredAt: a.registeredAt,
      isPrimary: a.isPrimary,
    }));

    res.json({ success: true, admins: sanitized });
  });

  // Update or Create Friend Account (Admin 2) - Requires active admin session
  app.post('/api/admin/update-friend', (req: Request, res: Response): void => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : req.body.token;
    const session = getSessionFromToken(token);

    if (!session) {
      res.status(401).json({ success: false, error: 'Unauthorized. Only active admins can manage accounts.' });
      return;
    }

    const { name, email, password, designation, phone } = req.body;
    if (!name || !email || !password) {
      res.status(400).json({ success: false, error: 'Friend Name, Email, and initial Password are required.' });
      return;
    }

    if (password.length < 6) {
      res.status(400).json({ success: false, error: 'Password must be at least 6 characters long.' });
      return;
    }

    const admins = loadOrCreateAdmins();
    const { hash, salt } = hashPassword(password);

    // Find if admin 2 exists
    const friendIndex = admins.findIndex((a) => !a.isPrimary || a.id === 'ADM-FRIEND-02');

    const updatedFriend: AdminRecord = {
      id: friendIndex >= 0 ? admins[friendIndex].id : 'ADM-FRIEND-02',
      name: name.trim(),
      email: email.trim().toLowerCase(),
      role: 'admin',
      designation: (designation || 'Co-Administrator (Facilities & ERP)').trim(),
      department: 'Campus Estate & Facilities',
      phone: (phone || '+91 98710 22302').trim(),
      passwordHash: hash,
      salt: salt,
      registeredAt: new Date().toISOString(),
      isPrimary: false,
    };

    if (friendIndex >= 0) {
      admins[friendIndex] = updatedFriend;
    } else {
      admins.push(updatedFriend);
    }

    saveAdmins(admins);

    res.json({
      success: true,
      message: 'Second Administrator account configured successfully with secure PBKDF2 hashing.',
      admin: {
        id: updatedFriend.id,
        name: updatedFriend.name,
        email: updatedFriend.email,
        designation: updatedFriend.designation,
      },
    });
  });

  // Change Password for Currently Logged-in Admin
  app.post('/api/admin/change-password', (req: Request, res: Response): void => {
    const authHeader = req.headers.authorization;
    const token = authHeader?.startsWith('Bearer ') ? authHeader.slice(7) : req.body.token;
    const session = getSessionFromToken(token);

    if (!session) {
      res.status(401).json({ success: false, error: 'Unauthorized. Please log in first.' });
      return;
    }

    const { currentPassword, newPassword } = req.body;
    if (!newPassword || newPassword.length < 6) {
      res.status(400).json({ success: false, error: 'New password must be at least 6 characters long.' });
      return;
    }

    const admins = loadOrCreateAdmins();
    const adminIndex = admins.findIndex((a) => a.id === session.adminId);

    if (adminIndex === -1) {
      res.status(404).json({ success: false, error: 'Administrator profile not found.' });
      return;
    }

    // If current password provided, verify it
    if (currentPassword) {
      const isValid = verifyPassword(currentPassword, admins[adminIndex].passwordHash, admins[adminIndex].salt);
      if (!isValid) {
        res.status(400).json({ success: false, error: 'Current password does not match.' });
        return;
      }
    }

    // Hash new password
    const { hash, salt } = hashPassword(newPassword);
    admins[adminIndex].passwordHash = hash;
    admins[adminIndex].salt = salt;
    saveAdmins(admins);

    res.json({
      success: true,
      message: 'Administrator password updated securely.',
    });
  });

  // --- AI CHATBOT API ROUTE (GEMINI API) ---
  app.post('/api/chat', async (req: Request, res: Response): Promise<void> => {
    const { message, history } = req.body;
    const userPrompt = (message || '').trim();

    if (!userPrompt) {
      res.status(400).json({ error: 'Message cannot be empty.' });
      return;
    }

    if (!genAi) {
      // Graceful fallback if GEMINI_API_KEY not configured
      res.json({
        reply: `Thank you for contacting GNIOT CampusFix! I am your AI campus assistant.
Regarding "${userPrompt}":
- For urgent classroom/hostel issues (electricity, water, AC), please file a ticket via the "Report Issue" button.
- You can track existing tickets using your Tracking ID.
- Our maintenance response teams operate 24/7 across APJ Abdul Kalam Block, Tech Zone, and Hostels.`,
      });
      return;
    }

    try {
      // Build conversation contents
      const contents: Array<{ role: 'user' | 'model'; parts: Array<{ text: string }> }> = [];

      if (Array.isArray(history)) {
        for (const item of history.slice(-6)) {
          if (item && item.role && item.text) {
            contents.push({
              role: item.role === 'user' ? 'user' : 'model',
              parts: [{ text: item.text }],
            });
          }
        }
      }

      contents.push({
        role: 'user',
        parts: [{ text: userPrompt }],
      });

      let replyText = '';
      try {
        const response = await genAi.models.generateContent({
          model: 'gemini-2.5-flash',
          contents,
          config: {
            systemInstruction: GNIOT_SYSTEM_INSTRUCTION,
          },
        });
        replyText = response.text || '';
      } catch (firstErr: any) {
        console.warn('Primary model gemini-2.5-flash busy, attempting gemini-2.5-flash-lite...', firstErr?.message);
        try {
          const fallbackResp = await genAi.models.generateContent({
            model: 'gemini-2.5-flash-lite',
            contents,
            config: {
              systemInstruction: GNIOT_SYSTEM_INSTRUCTION,
            },
          });
          replyText = fallbackResp.text || '';
        } catch (secondErr: any) {
          console.warn('Gemini upstream unavailable, generating knowledge-grounded campus response:', secondErr?.message);
          // Contextual response grounded in GNIOT campus rules
          const lower = userPrompt.toLowerCase();
          if (lower.includes('ac') || lower.includes('air condition') || lower.includes('cool')) {
            replyText = `**Air Conditioning & Climate Maintenance:**\n- AC repairs in APJ Abdul Kalam Block and Hostels are handled by our dedicated Electrical Maintenance Wing.\n- Turnaround time: Typically within **2 to 4 hours** during academic hours.\n- **Next Steps:** Click the **"Report Maintenance Issue"** button above, choose **"Electrical / HVAC"**, select your block/room, and submit. You will receive an instant 6-character Tracking ID.`;
          } else if (lower.includes('wifi') || lower.includes('internet') || lower.includes('lan')) {
            replyText = `**Campus Wi-Fi & IT Support:**\n- Managed by Central ERP & IT Directorate.\n- Report any connectivity drops in hostel rooms or lab terminals through the ticket form under **"IT & Network"**.\n- For immediate emergency IT assistance, you can also contact **ayushjaiswal272008@gmail.com**.`;
          } else if (lower.includes('hostel') || lower.includes('room') || lower.includes('warden')) {
            replyText = `**Hostel Maintenance Protocol:**\n- Hostels (Boys Hostels 1-3 & Girls Hostels 1-2) have dedicated 24/7 caretakers.\n- Common issues like plumbing, electrical sockets, or carpentering can be submitted anytime.\n- Emergency warden helpline is active 24/7.`;
          } else {
            replyText = `**GNIOT CampusFix Support:**\nThank you for reaching out regarding: *"${userPrompt}"*\n\n1. **Lodge a Complaint:** Use the **"Report Issue"** button on this page to alert maintenance technicians immediately.\n2. **Track Status:** Enter your 6-character Ticket ID in the **"Track Status"** tab to see technician assignment and live progress.\n3. **Administrative Inquiries:** Handled by ERP Directorate (Admin: Ayush Jaiswal).`;
          }
        }
      }

      res.json({ reply: replyText });
    } catch (err: any) {
      console.error('Gemini API chat error:', err);
      res.status(500).json({
        error: 'Failed to process chat message with Gemini API.',
        details: err?.message || 'Internal server error',
      });
    }
  });

  // Serve public static assets
  app.use(express.static(path.resolve(__dirname, 'public')));

  // --- VITE MIDDLEWARE SETUP ---
  if (process.env.NODE_ENV !== 'production') {
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    app.use(express.static(path.resolve(__dirname, 'dist')));
    app.get('*', (_req: Request, res: Response) => {
      res.sendFile(path.resolve(__dirname, 'dist', 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`[CampusFix Server] Full-Stack server running on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start server:', err);
  process.exit(1);
});
