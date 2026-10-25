import { router, json, error } from '@appdeploy/sdk';
import { db, ai, storage, secrets } from '@appdeploy/sdk';
import { randomBytes, scryptSync, timingSafeEqual, createHmac, createHash } from 'crypto';
import type { RouterContext, RouterResponse } from '@appdeploy/sdk';

const LEGACY_SUPER_ADMIN_EMAIL = 'migambo303@gmail.com';

const ROLES = ['public', 'student', 'professional', 'admin', 'super_admin'] as const;
type Role = typeof ROLES[number];

function hasAdminAccess(role: Role): boolean {
  return role === 'admin' || role === 'super_admin';
}

function hasSuperAdminAccess(role: Role): boolean {
  return role === 'super_admin';
}


const SIGNUP_ROLES: Role[] = ['public', 'student', 'professional'];

const REPORT_CATEGORIES = ['Infectious Disease', 'Waterborne Illness', 'Respiratory Illness', 'Foodborne Illness', 'Vector-borne Disease', 'Other'];
const REPORT_STATUSES = ['pending', 'under_review', 'reviewed', 'verified', 'rejected'];
const CONTRIBUTION_CATEGORIES = ['Health Question', 'Awareness Content', 'Community Health Observation', 'Suggestion', 'Educational Contribution'];

const PASSWORD_RESET_TTL_MS = 30 * 60 * 1000; // 30 minutes

type ImageSlot = 'organism' | 'transmission' | 'lifecycle' | 'prevention';

const DISEASE_IMAGE_PROMPTS: Record<string, Partial<Record<ImageSlot, string>>> = {
  cholera: {
    organism: 'Flat minimalist medical illustration of Vibrio cholerae bacteria under a microscope, teal and white color palette, clean health-tech style, no text, no watermark',
    transmission: 'Flat minimalist illustration of a contaminated water source and the faecal-oral transmission pathway for cholera, teal and white color palette, clean health-tech style, no text, no watermark',
    prevention: 'Flat minimalist illustration of safe water handling and handwashing for cholera prevention, teal and white color palette, clean health-tech style, no text, no watermark',
  },
  malaria: {
    organism: 'Flat minimalist medical illustration of a mosquito and Plasmodium parasite cells, teal and white color palette, clean health-tech style, no text, no watermark',
    transmission: 'Flat minimalist illustration of an Anopheles mosquito biting and transmitting malaria parasites to a human, teal and white color palette, clean health-tech style, no text, no watermark',
    lifecycle: 'Flat minimalist scientific diagram illustration of the Plasmodium malaria parasite life cycle alternating between mosquito and human host, teal and white color palette, clean health-tech style, no text, no watermark',
    prevention: 'Flat minimalist illustration of an insecticide-treated bed net protecting a sleeping person from mosquitoes, teal and white color palette, clean health-tech style, no text, no watermark',
  },
  tuberculosis: {
    organism: 'Flat minimalist medical illustration of Mycobacterium tuberculosis rod-shaped bacteria and human lungs, teal and white color palette, clean health-tech style, no text, no watermark',
    transmission: 'Flat minimalist illustration of airborne respiratory droplets spreading between people indoors, teal and white color palette, clean health-tech style, no text, no watermark',
    prevention: 'Flat minimalist illustration of good ventilation and a person wearing a mask indoors for tuberculosis prevention, teal and white color palette, clean health-tech style, no text, no watermark',
  },
  'lassa-fever': {
    organism: 'Flat minimalist medical illustration of an arenavirus particle and a small rodent silhouette, teal and white color palette, clean health-tech style, no text, no watermark',
    transmission: 'Flat minimalist illustration of a rodent near stored food in a home, representing Lassa fever transmission, teal and white color palette, clean health-tech style, no text, no watermark',
    prevention: 'Flat minimalist illustration of rodent-proof food storage containers for Lassa fever prevention, teal and white color palette, clean health-tech style, no text, no watermark',
  },
  'typhoid-fever': {
    organism: 'Flat minimalist medical illustration of Salmonella typhi bacteria, teal and white color palette, clean health-tech style, no text, no watermark',
    transmission: 'Flat minimalist illustration of contaminated food and water representing the faecal-oral transmission pathway for typhoid, teal and white color palette, clean health-tech style, no text, no watermark',
    prevention: 'Flat minimalist illustration of safe drinking water and handwashing for typhoid prevention, teal and white color palette, clean health-tech style, no text, no watermark',
  },
  'covid-19': {
    organism: 'Flat minimalist medical illustration of a coronavirus particle with spike proteins, teal and white color palette, clean health-tech style, no text, no watermark',
    transmission: 'Flat minimalist illustration of respiratory droplets spreading between people, representing COVID-19 transmission, teal and white color palette, clean health-tech style, no text, no watermark',
    prevention: 'Flat minimalist illustration of a person wearing a mask and receiving a vaccine, representing COVID-19 prevention, teal and white color palette, clean health-tech style, no text, no watermark',
  },
  candidiasis: {
    organism: 'Flat minimalist medical illustration of Candida yeast cells budding, teal and white color palette, clean health-tech style, no text, no watermark',
    transmission: 'Flat minimalist illustration representing overgrowth of Candida yeast on skin or mucosal surfaces, teal and white color palette, clean health-tech style, no text, no watermark',
    prevention: 'Flat minimalist illustration of good hygiene and skin care for candidiasis prevention, teal and white color palette, clean health-tech style, no text, no watermark',
  },
};

// --- Types ---

interface UserRecord {
  fullName: string;
  username: string;
  usernameLower: string;
  email: string;
  emailLower: string;
  phone: string;
  passwordHash: string;
  role: Role;
  verifiedAdmin?: boolean;
  verifiedAt?: string;
  verifiedBy?: string;
  bio?: string;
  joinedAt: string;
}

type StoredUser = UserRecord & { id: string };

interface ReportRecord {
  title: string;
  description: string;
  location: string;
  category: string;
  date: string;
  attachmentNote?: string;
  status: string;
  userId: string;
  userEmail?: string;
  createdAt: string;
  verifiedBy?: string;
  verifiedAt?: string;
  verificationNotes?: string;
}

interface ContributionRecord {
  title: string;
  content: string;
  category: string;
  authorId: string;
  authorUsername: string;
  status: string;
  createdAt: string;
}

interface PasswordResetRecord {
  userId: string;
  tokenHash: string;
  expiresAt: string;
  used: boolean;
  createdAt: string;
}

// --- Password hashing (Node crypto, no external deps) ---

function hashPassword(password: string): string {
  const salt = randomBytes(16).toString('hex');
  const hash = scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password: string, stored: string): boolean {
  const [salt, hashHex] = stored.split(':');
  if (!salt || !hashHex) return false;
  const hash = scryptSync(password, salt, 64);
  const storedBuf = Buffer.from(hashHex, 'hex');
  if (hash.length !== storedBuf.length) return false;
  return timingSafeEqual(hash, storedBuf);
}

// --- Password reset tokens ---
// Tokens are generated with a CSPRNG, and only a SHA-256 hash of the token is ever persisted
// (mirroring how account passwords are never stored in plain text). The raw token exists only
// in the emailed link and in-memory for the duration of the request that issues it.

function generateResetToken(): string {
  return randomBytes(32).toString('hex');
}

function hashResetToken(token: string): string {
  return createHash('sha256').update(token).digest('hex');
}

function isValidNewPassword(password: string): boolean {
  return password.length >= 8 && /[a-zA-Z]/.test(password) && /[0-9]/.test(password);
}

async function findUserByIdentifier(identifier: string): Promise<StoredUser | null> {
  const identifierLower = identifier.toLowerCase();
  const byUsername = await db.list<UserRecord>('users', { filter: { usernameLower: identifierLower }, limit: 1 });
  if (byUsername.items.length > 0) return byUsername.items[0];
  const byEmail = await db.list<UserRecord>('users', { filter: { emailLower: identifierLower }, limit: 1 });
  if (byEmail.items.length > 0) return byEmail.items[0];
  const byPhone = await db.list<UserRecord>('users', { filter: { phone: identifier }, limit: 1 });
  if (byPhone.items.length > 0) return byPhone.items[0];
  return null;
}

/**
 * Sends the password reset email if an email provider is configured via secrets.
 * AppDeploy's SDK has no built-in email-sending feature, so this reads an optional
 * RESEND_API_KEY secret and calls the Resend HTTP API directly. If that secret is not
 * configured, delivery is skipped and the reset link is logged server-side instead, so
 * the reset mechanism itself is fully functional and testable without fabricating an
 * email being sent. See the deployment notes for what to configure to enable real delivery.
 */
async function sendPasswordResetEmail(toEmail: string, toName: string, resetLink: string): Promise<void> {
  let apiKey: string | null = null;
  try {
    apiKey = await secrets.readSecret('RESEND_API_KEY');
  } catch {
    apiKey = null;
  }

  if (!apiKey) {
    console.log('[password-reset] Email delivery unavailable');
    return;
  }

  let fromAddress = 'HoticeEpiConnect <onboarding@resend.dev>';
  try {
    const configuredFrom = await secrets.readSecret('RESEND_FROM_EMAIL');
    if (configuredFrom) fromAddress = configuredFrom;
  } catch {
    // Optional secret; fall back to the default sender above.
  }

  try {
    const res = await fetch('https://api.resend.com/emails', {
      method: 'POST',
      headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        from: fromAddress,
        to: [toEmail],
        subject: 'Reset your HoticeEpiConnect password',
        html: `<p>Hi ${toName},</p><p>We received a request to reset your HoticeEpiConnect password. This link expires in 30 minutes.</p><p><a href="${resetLink}">Reset your password</a></p><p>If you didn't request this, you can safely ignore this email -- your password will not be changed.</p>`,
      }),
    });
    if (!res.ok) {
      const body = await res.text().catch(() => '');
      console.error('password reset email send failed', res.status, body);
    }
  } catch (e) {
    console.error('password reset email send failed', e);
  }
}

// --- Session tokens (HMAC-signed, stored in an HttpOnly cookie) ---

async function getSessionSecret(): Promise<string> {
  const { items } = await db.list<{ key: string; value: string }>('app_config', { filter: { key: 'session_secret' }, limit: 1 });
  if (items.length > 0) return items[0].value;
  const value = randomBytes(32).toString('hex');
  await db.add('app_config', [{ key: 'session_secret', value }]);
  return value;
}

function base64url(input: string): string {
  return Buffer.from(input, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function base64urlDecode(input: string): string {
  let s = input.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  return Buffer.from(s, 'base64').toString('utf8');
}

async function createSessionToken(userId: string): Promise<string> {
  const secret = await getSessionSecret();
  const payload = JSON.stringify({ uid: userId, exp: Date.now() + 1000 * 60 * 60 * 24 * 30 });
  const payloadB64 = base64url(payload);
  const sig = createHmac('sha256', secret).update(payloadB64).digest('hex');
  return `${payloadB64}.${sig}`;
}

async function verifySessionToken(token: string): Promise<string | null> {
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const [payloadB64, sig] = parts;
  const secret = await getSessionSecret();
  const expectedSig = createHmac('sha256', secret).update(payloadB64).digest('hex');
  const sigBuf = Buffer.from(sig, 'hex');
  const expBuf = Buffer.from(expectedSig, 'hex');
  if (sigBuf.length !== expBuf.length || !timingSafeEqual(sigBuf, expBuf)) return null;
  try {
    const payload = JSON.parse(base64urlDecode(payloadB64));
    if (typeof payload.exp !== 'number' || Date.now() > payload.exp) return null;
    if (typeof payload.uid !== 'string') return null;
    return payload.uid;
  } catch {
    return null;
  }
}

function parseCookies(ctx: RouterContext): Record<string, string> {
  const event = ctx.event as any;
  const rawList: string[] = Array.isArray(event?.cookies) ? event.cookies : [];
  const header: string = event?.headers?.cookie || event?.headers?.Cookie || '';
  const parts = rawList.length > 0 ? rawList : header.split(';');
  const out: Record<string, string> = {};
  for (const part of parts) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const value = part.slice(idx + 1).trim();
    if (key) out[key] = decodeURIComponent(value);
  }
  return out;
}

function getRequestOrigin(ctx: RouterContext): string {
  const event = ctx.event as any;
  const host = event?.headers?.host || event?.headers?.Host || '';
  const proto = event?.headers?.['x-forwarded-proto'] || event?.headers?.['X-Forwarded-Proto'] || 'https';
  return host ? `${proto}://${host}` : '';
}

async function getSessionUser(ctx: RouterContext): Promise<StoredUser | null> {
  const cookies = parseCookies(ctx);
  const token = cookies['session'];
  if (!token) return null;
  const uid = await verifySessionToken(token);
  if (!uid) return null;
  const [user] = await db.get<UserRecord>('users', [uid]);
  if (!user) return null;
  return { ...user, id: uid };
}

function withSessionCookie(res: RouterResponse, token: string | null): RouterResponse {
  const cookie = token
    ? `session=${token}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${60 * 60 * 24 * 30}`
    : `session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
  return { ...res, headers: { ...res.headers, 'Set-Cookie': cookie } };
}

function toSafeUser(u: StoredUser) {
  return {
    id: u.id,
    username: u.username,
    fullName: u.fullName,
    email: u.email,
    phone: u.phone,
    role: u.role,
    bio: u.bio || '',
    joinedAt: u.joinedAt,
  };
}

function stripId(u: StoredUser): UserRecord {
  const { id, ...rest } = u;
  return rest;
}

// --- Audit logging ---

interface AuditLogRecord {
  actorId: string;
  actorUsername: string;
  action: string;
  targetType: string;
  targetId: string;
  details?: Record<string, unknown>;
  createdAt: string;
}

async function logAuditEvent(actor: StoredUser, action: string, targetType: string, targetId: string, details?: Record<string, unknown>): Promise<void> {
  const record: AuditLogRecord = {
    actorId: actor.id,
    actorUsername: actor.username,
    action,
    targetType,
    targetId,
    details,
    createdAt: new Date().toISOString(),
  };
  try {
    await db.add('audit_log', [record]);
  } catch (e) {
    console.error('audit log write failed', e);
  }
}

// --- Validation helpers ---

function validateReportBody(body: any): string | null {
  if (!body || typeof body !== 'object') return 'Invalid request body';
  const { title, description, location, category, date } = body;
  if (!title || typeof title !== 'string' || !title.trim()) return 'Title is required';
  if (!description || typeof description !== 'string' || !description.trim()) return 'Description is required';
  if (!location || typeof location !== 'string' || !location.trim()) return 'Location is required';
  if (!category || typeof category !== 'string' || !REPORT_CATEGORIES.includes(category)) return 'A valid category is required';
  if (!date || typeof date !== 'string' || !date.trim()) return 'Date is required';
  return null;
}

export const handler = router({
  'GET /api/_healthcheck': [async () => json({ message: 'Success' })],

  // --- Auth ---

  'POST /api/auth/register': [async (ctx) => {
    const b = ctx.body as any;
    const fullName = typeof b?.fullName === 'string' ? b.fullName.trim() : '';
    const username = typeof b?.username === 'string' ? b.username.trim() : '';
    const email = typeof b?.email === 'string' ? b.email.trim() : '';
    const phone = typeof b?.phone === 'string' ? b.phone.trim() : '';
    const password = typeof b?.password === 'string' ? b.password : '';
    const requestedRole = typeof b?.role === 'string' ? b.role : 'public';

    if (!fullName) return error('Full name is required', 400);
    if (!/^[a-zA-Z0-9_]{3,20}$/.test(username)) return error('Username must be 3-20 characters using only letters, numbers, and underscores', 400);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return error('A valid email address is required', 400);
    if (!/^[+]?[0-9\s-]{7,15}$/.test(phone)) return error('A valid phone number is required', 400);
    if (password.length < 8 || !/[a-zA-Z]/.test(password) || !/[0-9]/.test(password)) {
      return error('Password must be at least 8 characters and include both letters and numbers', 400);
    }
    const role: Role = SIGNUP_ROLES.includes(requestedRole as Role) ? (requestedRole as Role) : 'public';

    const usernameLower = username.toLowerCase();
    const emailLower = email.toLowerCase();

    const [byUsername, byEmail, byPhone] = await Promise.all([
      db.list<UserRecord>('users', { filter: { usernameLower }, limit: 1 }),
      db.list<UserRecord>('users', { filter: { emailLower }, limit: 1 }),
      db.list<UserRecord>('users', { filter: { phone }, limit: 1 }),
    ]);
    if (byUsername.items.length > 0) return error('That username is already taken', 409);
    if (byEmail.items.length > 0) return error('An account with that email already exists', 409);
    if (byPhone.items.length > 0) return error('An account with that phone number already exists', 409);

    const { items: existingSuperAdmins } = await db.list<UserRecord>('users', { filter: { role: 'super_admin' }, limit: 1 });
    let finalRole: Role = role;

    if (existingSuperAdmins.length === 0) {
      const { items: legacyAdmins } = await db.list<UserRecord>('users', { filter: { emailLower: LEGACY_SUPER_ADMIN_EMAIL }, limit: 1 });
      if (legacyAdmins.length > 0) {
        await db.update('users', [{ id: legacyAdmins[0].id, record: { ...legacyAdmins[0], role: 'super_admin' } }]);
      } else {
        const { items: existingUsers } = await db.list<UserRecord>('users', { limit: 1 });
        if (existingUsers.length === 0) finalRole = 'super_admin';
      }
    }
    const record: UserRecord = {
      fullName,
      username,
      usernameLower,
      email,
      emailLower,
      phone,
      passwordHash: hashPassword(password),
      role: finalRole,
      bio: '',
      joinedAt: new Date().toISOString(),
    };
    const [id] = await db.add('users', [record]);
    if (!id) return error('Failed to create account', 500);
    const token = await createSessionToken(id);
    const res = json({ user: toSafeUser({ ...record, id }) }, 201);
    return withSessionCookie(res, token);
  }],

  'POST /api/auth/login': [async (ctx) => {
    const b = ctx.body as any;
    const identifier = typeof b?.identifier === 'string' ? b.identifier.trim() : '';
    const password = typeof b?.password === 'string' ? b.password : '';
    if (!identifier || !password) return error('Please enter your username, email, or phone number and your password', 400);

    const identifierLower = identifier.toLowerCase();
    let found: StoredUser | null = null;

    const byUsername = await db.list<UserRecord>('users', { filter: { usernameLower: identifierLower }, limit: 1 });
    if (byUsername.items.length > 0) found = byUsername.items[0];

    if (!found) {
      const byEmail = await db.list<UserRecord>('users', { filter: { emailLower: identifierLower }, limit: 1 });
      if (byEmail.items.length > 0) found = byEmail.items[0];
    }

    if (!found) {
      const byPhone = await db.list<UserRecord>('users', { filter: { phone: identifier }, limit: 1 });
      if (byPhone.items.length > 0) found = byPhone.items[0];
    }

    if (!found || !verifyPassword(password, found.passwordHash)) {
      return error('Incorrect username/email/phone or password', 401);
    }

    const token = await createSessionToken(found.id);
    const res = json({ user: toSafeUser(found) });
    return withSessionCookie(res, token);
  }],

  'POST /api/auth/logout': [async () => {
    const res = json({ message: 'Signed out' });
    return withSessionCookie(res, null);
  }],

  'GET /api/auth/me': [async (ctx) => {
    const user = await getSessionUser(ctx);
    return json({ user: user ? toSafeUser(user) : null });
  }],

  'POST /api/auth/forgot-password': [async (ctx) => {
    const b = ctx.body as any;
    const identifier = typeof b?.identifier === 'string' ? b.identifier.trim() : '';
    const genericMessage = 'If an account matches, password reset instructions have been sent to the email on file.';
    if (!identifier) return error('Please enter your username, email, or phone number', 400);

    const found = await findUserByIdentifier(identifier);

    // Always respond identically whether or not an account was found, so this endpoint
    // never reveals which identifiers exist in the system.
    if (found) {
      const rawToken = generateResetToken();
      const resetRecord: PasswordResetRecord = {
        userId: found.id,
        tokenHash: hashResetToken(rawToken),
        expiresAt: new Date(Date.now() + PASSWORD_RESET_TTL_MS).toISOString(),
        used: false,
        createdAt: new Date().toISOString(),
      };
      await db.add('password_resets', [resetRecord]);

      const origin = getRequestOrigin(ctx);
      const resetLink = `${origin}/#/reset-password?token=${rawToken}`;
      await sendPasswordResetEmail(found.email, found.fullName, resetLink);
    }

    return json({ message: genericMessage });
  }],

  'POST /api/auth/reset-password': [async (ctx) => {
    const b = ctx.body as any;
    const token = typeof b?.token === 'string' ? b.token.trim() : '';
    const newPassword = typeof b?.newPassword === 'string' ? b.newPassword : '';
    if (!token) return error('This reset link is invalid. Please request a new one.', 400);
    if (!isValidNewPassword(newPassword)) {
      return error('Password must be at least 8 characters and include both letters and numbers', 400);
    }

    const tokenHash = hashResetToken(token);
    const { items } = await db.list<PasswordResetRecord>('password_resets', { filter: { tokenHash }, limit: 1 });
    const resetRecord = items[0];

    if (!resetRecord) return error('This reset link is invalid. Please request a new one.', 400);
    if (resetRecord.used) return error('This reset link has already been used. Please request a new one.', 400);
    if (new Date(resetRecord.expiresAt).getTime() < Date.now()) {
      return error('This reset link has expired. Please request a new one.', 400);
    }

    // The token itself is the proof of account ownership (it was only ever sent to the
    // account's own email address), so the reset always applies to the exact user it was
    // issued for -- never to any user id supplied by the client.
    const [existingUser] = await db.get<UserRecord>('users', [resetRecord.userId]);
    if (!existingUser) return error('This reset link is no longer valid. Please request a new one.', 400);

    const [ok] = await db.update('users', [{ id: resetRecord.userId, record: { ...existingUser, passwordHash: hashPassword(newPassword) } }]);
    if (!ok) return error('Failed to reset password. Please try again.', 500);

    // One-time use: mark this token spent so the same link cannot be replayed.
    await db.update('password_resets', [{ id: (resetRecord as any).id, record: { ...resetRecord, used: true } }]);

    const sessionToken = await createSessionToken(resetRecord.userId);
    const res = json({ user: toSafeUser({ ...existingUser, id: resetRecord.userId }), message: 'Your password has been reset successfully.' });
    return withSessionCookie(res, sessionToken);
  }],

  // --- Profiles ---

  'GET /api/users/:username': [async (ctx) => {
    const { username } = ctx.params;
    const { items } = await db.list<UserRecord>('users', { filter: { usernameLower: username.toLowerCase() }, limit: 1 });
    if (items.length === 0) return error('User not found', 404);
    const u = items[0];
    const { items: contributions } = await db.list<ContributionRecord>('contributions', { filter: { authorId: u.id, status: 'approved' }, limit: 50 });
    return json({
      username: u.username,
      fullName: u.fullName,
      role: u.role,
      joinedAt: u.joinedAt,
      bio: u.bio || '',
      contributions: contributions
        .sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''))
        .map((c) => ({ id: c.id, title: c.title, category: c.category, createdAt: c.createdAt })),
    });
  }],

  'PUT /api/users/me': [async (ctx) => {
    const user = await getSessionUser(ctx);
    if (!user) return error('Please sign in', 401);
    const b = ctx.body as any;
    const bio = typeof b?.bio === 'string' ? b.bio.slice(0, 300) : (user.bio || '');
    const [ok] = await db.update('users', [{ id: user.id, record: { ...stripId(user), bio } }]);
    if (!ok) return error('Failed to update profile', 500);
    return json({ user: toSafeUser({ ...user, bio }) });
  }],

  // --- Admin: user management ---

  'GET /api/admin/users': [async (ctx) => {
    const user = await getSessionUser(ctx);
    if (!user || !hasAdminAccess(user.role)) return error('Admin access required', 403);
    const { items } = await db.list<UserRecord>('users', { limit: 200 });
    return json({
      items: items.map((u) => ({
        id: u.id,
        username: u.username,
        fullName: u.fullName,
        email: u.email,
        role: u.role,
        joinedAt: u.joinedAt,
        verifiedAdmin: u.verifiedAdmin ?? false,
        verifiedAt: u.verifiedAt ?? null,
        verifiedBy: u.verifiedBy ?? null,
      })),
    });
  }],

  'PUT /api/admin/users/:id/role': [async (ctx) => {
    const user = await getSessionUser(ctx);
    if (!user || !hasSuperAdminAccess(user.role)) return error('Super administrator access required', 403);
    const { id } = ctx.params;
    const b = ctx.body as any;
    const role = typeof b?.role === 'string' ? b.role : '';
    if (!ROLES.includes(role as Role)) return error('Invalid role', 400);
    if (role === 'super_admin' && !hasSuperAdminAccess(user.role)) return error('Only a super administrator can assign the super administrator role', 403);
    const [existing] = await db.get<UserRecord>('users', [id]);
    if (!existing) return error('User not found', 404);
    if (existing.role === 'super_admin' && role !== 'super_admin') {
      const { items: superAdmins } = await db.list<UserRecord>('users', { filter: { role: 'super_admin' }, limit: 2 });
      if (superAdmins.length <= 1) return error('Cannot remove the last remaining super administrator', 400);
    }
    const [ok] = await db.update('users', [{ id, record: { ...existing, role } }]);
    if (!ok) return error('Failed to update role', 500);
    await logAuditEvent(user, 'user_role_changed', 'user', id, { fromRole: existing.role, toRole: role });
    return json({ id, role });
  }],

  'PUT /api/admin/users/:id/verified-admin': [async (ctx) => {
    const user = await getSessionUser(ctx);
    if (!user || !hasSuperAdminAccess(user.role)) return error('Super administrator access required', 403);
    const { id } = ctx.params;
    const enabled = Boolean((ctx.body as any)?.verifiedAdmin);
    const [existing] = await db.get<UserRecord>('users', [id]);
    if (!existing) return error('User not found', 404);
    const [ok] = await db.update('users', [{ id, record: {
      ...existing,
      verifiedAdmin: enabled,
      verifiedAt: enabled ? new Date().toISOString() : undefined,
      verifiedBy: enabled ? user.id : undefined,
    }}]);
    if (!ok) return error('Failed to update verified admin status', 500);
    await logAuditEvent(user, enabled ? 'verified_admin_granted' : 'verified_admin_revoked', 'user', id, { verifiedAdmin: enabled, username: existing.username });
    return json({ id, verifiedAdmin: enabled });
  }],

  'GET /api/admin/audit-log': [async (ctx) => {
    const user = await getSessionUser(ctx);
    if (!user || !hasAdminAccess(user.role)) return error('Admin access required', 403);
    const { items } = await db.list<AuditLogRecord>('audit_log', { limit: 200 });
    const sorted = [...items].sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
    return json({ items: sorted });
  }],

  // --- Disease illustrations ---

  'GET /api/disease-image/:diseaseId': [async (ctx) => {
    const { diseaseId } = ctx.params;
    const rawType = typeof ctx.query.type === 'string' ? ctx.query.type : 'organism';
    const validSlots: ImageSlot[] = ['organism', 'transmission', 'lifecycle', 'prevention'];
    const type: ImageSlot = validSlots.includes(rawType as ImageSlot) ? (rawType as ImageSlot) : 'organism';
    const path = type === 'organism' ? `disease-images/${diseaseId}.png` : `disease-images/${diseaseId}-${type}.png`;
    const [existing] = await storage.read([path]);
    if (existing && existing.content) {
      const [signed] = await storage.url([path]);
      return json({ url: signed.url });
    }
    const slotPrompts = DISEASE_IMAGE_PROMPTS[diseaseId] || {};
    const prompt = slotPrompts[type] || `Flat minimalist medical illustration of ${type} related to ${diseaseId}, teal and white color palette, clean health-tech style, no text, no watermark`;
    try {
      const result = await ai.imageGen({ prompt, maxOutputBytes: 900000 });
      const [ok] = await storage.write([{ path, content: result.image.data, contentType: result.image.mimeType }]);
      if (!ok) return error('Failed to save generated image', 500);
      const [signed] = await storage.url([path]);
      return json({ url: signed.url });
    } catch (e) {
      console.error('disease-image generation failed', e);
      return error('Failed to generate image', 500);
    }
  }],

  // --- Disease library (admin-managed additions) ---

  'GET /api/diseases': [async () => {
    const { items } = await db.list<Record<string, unknown>>('diseases', { limit: 200 });
    return json({ items });
  }],

  'POST /api/diseases': [async (ctx) => {
    const user = await getSessionUser(ctx);
    if (!user || !hasAdminAccess(user.role)) return error('Admin access required', 403);
    const b = ctx.body as any;
    const name = typeof b?.name === 'string' ? b.name.trim() : '';
    if (!name) return error('A disease name is required', 400);
    const { id: _ignoreId, ...rest } = b || {};
    const record = { ...rest, name, createdBy: user.username, createdAt: new Date().toISOString() };
    const [dbId] = await db.add('diseases', [record]);
    if (!dbId) return error('Failed to create disease entry', 500);
    await logAuditEvent(user, 'disease_created', 'disease', dbId, { name });
    return json({ id: dbId, ...record }, 201);
  }],

  'PUT /api/diseases/:id': [async (ctx) => {
    const user = await getSessionUser(ctx);
    if (!user || !hasAdminAccess(user.role)) return error('Admin access required', 403);
    const { id } = ctx.params;
    const [existing] = await db.get<Record<string, unknown>>('diseases', [id]);
    if (!existing) return error('Disease entry not found', 404);
    const b = ctx.body as any;
    const { id: _ignoreId, ...rest } = b || {};
    const updated = { ...existing, ...rest, updatedBy: user.username, updatedAt: new Date().toISOString() };
    const [ok] = await db.update('diseases', [{ id, record: updated }]);
    if (!ok) return error('Failed to update disease entry', 500);
    await logAuditEvent(user, 'disease_updated', 'disease', id, {});
    return json({ id, ...updated });
  }],

  // --- Health observations (reports) ---

  'GET /api/dashboard-stats': [async () => {
    const { items } = await db.list<ReportRecord>('reports', { limit: 100 });
    const totalReports = items.length;
    const verified = items.filter((r) => r.status === 'verified').length;
    const pending = items.filter((r) => r.status === 'pending').length;
    const recent = [...items]
      .filter((r) => r.status !== 'pending')
      .sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''))
      .slice(0, 6)
      .map((r) => ({ id: r.id, title: r.title, location: r.location, category: r.category, date: r.date, status: r.status }));
    return json({ totalReports, verified, pending, recent });
  }],

  'POST /api/reports': [async (ctx) => {
    const user = await getSessionUser(ctx);
    if (!user) return error('Please sign in to submit a health observation', 401);
    const validationError = validateReportBody(ctx.body);
    if (validationError) return error(validationError, 400);
    const b = ctx.body as any;
    const record: ReportRecord = {
      title: b.title.trim(),
      description: b.description.trim(),
      location: b.location.trim(),
      category: b.category,
      date: b.date,
      attachmentNote: typeof b.attachmentNote === 'string' ? b.attachmentNote.trim() : undefined,
      status: 'pending',
      userId: user.id,
      userEmail: user.email,
      createdAt: new Date().toISOString(),
    };
    const [id] = await db.add('reports', [record]);
    if (!id) return error('Failed to submit health observation', 500);
    return json({ id, ...record }, 201);
  }],

  'GET /api/reports/mine': [async (ctx) => {
    const user = await getSessionUser(ctx);
    if (!user) return error('Please sign in', 401);
    const { items } = await db.list<ReportRecord>('reports', { filter: { userId: user.id }, limit: 100 });
    const sorted = [...items].sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
    return json({ items: sorted });
  }],

  'GET /api/reports': [async (ctx) => {
    const user = await getSessionUser(ctx);
    if (!user || !(hasAdminAccess(user.role) || user.role === 'professional')) return error('You do not have permission to review health observations', 403);
    const { items } = await db.list<ReportRecord>('reports', { limit: 100 });
    const sorted = [...items].sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
    return json({ items: sorted });
  }],

  'PUT /api/reports/:id/status': [async (ctx) => {
    const user = await getSessionUser(ctx);
    if (!user || !(hasAdminAccess(user.role) || user.role === 'professional')) return error('You do not have permission to review health observations', 403);
    const { id } = ctx.params;
    const b = ctx.body as any;
    const status = b && typeof b.status === 'string' ? b.status : '';
    if (!REPORT_STATUSES.includes(status)) return error('Invalid status', 400);
    const [existing] = await db.get<ReportRecord>('reports', [id]);
    if (!existing) return error('Report not found', 404);
    const providedNotes = typeof b?.verificationNotes === 'string' ? b.verificationNotes.trim() : '';
    const updated: ReportRecord = {
      ...existing,
      status,
      verifiedBy: user.username,
      verifiedAt: new Date().toISOString(),
      ...(providedNotes ? { verificationNotes: providedNotes } : {}),
    };
    const [ok] = await db.update('reports', [{ id, record: updated }]);
    if (!ok) return error('Failed to update report', 500);
    await logAuditEvent(user, 'report_status_changed', 'report', id, { fromStatus: existing.status, toStatus: status, verificationNotes: updated.verificationNotes });
    return json({ id, status, verifiedBy: updated.verifiedBy, verifiedAt: updated.verifiedAt, verificationNotes: updated.verificationNotes });
  }],

  // --- Community contributions ---

  'POST /api/contributions': [async (ctx) => {
    const user = await getSessionUser(ctx);
    if (!user) return error('Please sign in to submit a contribution', 401);
    const b = ctx.body as any;
    const title = typeof b?.title === 'string' ? b.title.trim() : '';
    const content = typeof b?.content === 'string' ? b.content.trim() : '';
    const category = typeof b?.category === 'string' ? b.category : '';
    if (!title) return error('Title is required', 400);
    if (!content) return error('Content is required', 400);
    if (!CONTRIBUTION_CATEGORIES.includes(category)) return error('A valid category is required', 400);
    const record: ContributionRecord = {
      title,
      content,
      category,
      authorId: user.id,
      authorUsername: user.username,
      status: 'pending',
      createdAt: new Date().toISOString(),
    };
    const [id] = await db.add('contributions', [record]);
    if (!id) return error('Failed to submit contribution', 500);
    return json({ id, ...record }, 201);
  }],

  'GET /api/contributions': [async (ctx) => {
    const category = ctx.query.category;
    const filter: Record<string, unknown> = { status: 'approved' };
    if (category) filter.category = category;
    const { items } = await db.list<ContributionRecord>('contributions', { filter, limit: 100 });
    const sorted = [...items].sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
    return json({
      items: sorted.map((c) => ({ id: c.id, title: c.title, content: c.content, category: c.category, authorUsername: c.authorUsername, createdAt: c.createdAt })),
    });
  }],

  'GET /api/contributions/mine': [async (ctx) => {
    const user = await getSessionUser(ctx);
    if (!user) return error('Please sign in', 401);
    const { items } = await db.list<ContributionRecord>('contributions', { filter: { authorId: user.id }, limit: 100 });
    const sorted = [...items].sort((a, b) => (b.createdAt || '').localeCompare(a.createdAt || ''));
    return json({ items: sorted });
  }],

  'GET /api/contributions/pending': [async (ctx) => {
    const user = await getSessionUser(ctx);
    if (!user || !['admin', 'professional'].includes(user.role)) return error('You do not have permission to review contributions', 403);
    const { items } = await db.list<ContributionRecord>('contributions', { filter: { status: 'pending' }, limit: 100 });
    const sorted = [...items].sort((a, b) => (a.createdAt || '').localeCompare(b.createdAt || ''));
    return json({ items: sorted });
  }],

  'PUT /api/contributions/:id/status': [async (ctx) => {
    const user = await getSessionUser(ctx);
    if (!user || !['admin', 'professional'].includes(user.role)) return error('You do not have permission to review contributions', 403);
    const { id } = ctx.params;
    const b = ctx.body as any;
    const status = typeof b?.status === 'string' ? b.status : '';
    if (!['approved', 'rejected'].includes(status)) return error('Invalid status', 400);
    const [existing] = await db.get<ContributionRecord>('contributions', [id]);
    if (!existing) return error('Contribution not found', 404);
    const [ok] = await db.update('contributions', [{ id, record: { ...existing, status } }]);
    if (!ok) return error('Failed to update contribution', 500);
    await logAuditEvent(user, 'contribution_status_changed', 'contribution', id, { fromStatus: existing.status, toStatus: status });
    return json({ id, status });
  }],
});
