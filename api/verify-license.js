// Vercel API Route สำหรับ License Validation
// 🚀 Serverless License Server - ไม่ต้องรัน server เอง!

import { createClient } from '@supabase/supabase-js';

// Environment Variables
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;
const SECRET = process.env.LICENSE_SECRET || "CHANGE_ME_SECRET";

// สร้าง Supabase client
const supabase = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY);

// Rate limiting (ป้องกัน abuse)
const rateLimitMap = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 นาที
const RATE_LIMIT_MAX = 10; // 10 requests ต่อ IP ต่อนาที

function isRateLimited(ip) {
  const now = Math.floor(Date.now());
  const windowStart = now - RATE_LIMIT_WINDOW;
  
  if (!rateLimitMap.has(ip)) {
    rateLimitMap.set(ip, []);
  }
  
  const requests = rateLimitMap.get(ip);
  const validRequests = requests.filter(time => time > windowStart);
  
  if (validRequests.length >= RATE_LIMIT_MAX) {
    return true;
  }
  
  validRequests.push(now);
  rateLimitMap.set(ip, validRequests);
  
  // Clean up old entries
  if (rateLimitMap.size > 1000) {
    for (const [key, value] of rateLimitMap) {
      if (value.every(time => time <= windowStart)) {
        rateLimitMap.delete(key);
      }
    }
  }
  
  return false;
}

// Helper function สำหรับ sign response
async function jsonSigned(data, res) {
  const body = JSON.stringify(data);
  
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(SECRET),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  
  const sigBuf = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(body));
  const sigHex = Array.from(new Uint8Array(sigBuf))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");

  res.setHeader("Content-Type", "application/json");
  res.setHeader("X-Signature", sigHex);
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  
  return res.status(200).json(data);
}

export default async function handler(req, res) {
  // Get client IP for rate limiting
  const clientIP = req.headers['x-forwarded-for'] || 'unknown';

  // Handle CORS
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    res.setHeader('Access-Control-Allow-Origin', '*');
    return res.status(405).json({ error: 'Method not allowed' });
  }

  // Rate limiting check
  if (isRateLimited(clientIP)) {
    console.log(`[RATE LIMIT] IP ${clientIP} exceeded rate limit`);
    return await jsonSigned({ 
      success: false, 
      error: "rate_limit_exceeded" 
    }, res);
  }

  try {
    // Validate environment variables
    if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
      console.error('[CONFIG ERROR] Missing Supabase configuration');
      return await jsonSigned({ 
        success: false, 
        error: "server_misconfiguration" 
      }, res);
    }

    // รับข้อมูลจาก request body
    let body;
    try {
      body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    } catch (e) {
      console.log('[PARSE ERROR] Invalid JSON:', req.body);
      return await jsonSigned({ 
        success: false, 
        error: "invalid_json" 
      }, res);
    }
    const { license_key, machine_id, licenseKey, machineId } = body || {};
    
    const lk = license_key || licenseKey;
    const mid = machine_id || machineId;
    
    if (!lk || !mid) {
      console.log(`[INVALID REQUEST] Missing license_key or machine_id from IP ${clientIP}`);
      return await jsonSigned({ 
        success: false, 
        error: "invalid_payload" 
      }, res);
    }

    // 🔍 Validate license with new Supabase function
    const validationResult = await validateLicenseWithNewSystem(lk, mid, clientIP, req.headers['user-agent']);
    
    console.log(`[LICENSE CHECK] ${lk} for ${mid}: ${validationResult.success ? 'VALID' : 'INVALID'} (${validationResult.error || 'N/A'})`);
    
    return await jsonSigned({
      success: validationResult.success,
      status: validationResult.success ? "valid" : "invalid",
      reason: validationResult.error || validationResult.message || undefined,
      tier: validationResult.success ? validationResult.license_type : undefined,
      data: validationResult.success ? {
        license_type: validationResult.license_type,
        package_code: validationResult.package_code,
        expires_at: validationResult.expires_at,
        features: validationResult.features
      } : undefined
    }, res);
    
  } catch (error) {
    console.error('[LICENSE API] Unexpected error:', error);
    return await jsonSigned({ 
      success: false, 
      error: "server_error",
      detail: process.env.NODE_ENV === 'development' ? error.message : undefined
    }, res);
  }
}

// 🔍 New License Validation with Database Functions
async function validateLicenseWithNewSystem(licenseKey, machineId, ipAddress = null, userAgent = null) {
  try {
    console.log(`[DB FUNCTION] Validating license: ${licenseKey} for machine: ${machineId}`);
    
    // Use the new database function for license validation
    const { data, error } = await supabase.rpc('validate_license_key', {
      p_license_key: licenseKey,
      p_machine_id: machineId,
      p_ip_address: ipAddress,
      p_user_agent: userAgent,
      p_device_fingerprint: null
    });

    if (error) {
      console.error('[DB FUNCTION ERROR]', error);
      return {
        success: false,
        error: 'database_error',
        message: 'เกิดข้อผิดพลาดของระบบ'
      };
    }

    // Log activity
    try {
      await supabase.rpc('log_license_activity', {
        p_license_key: licenseKey,
        p_activity_type: 'validation',
        p_machine_id: machineId,
        p_success: data.success,
        p_error_code: data.success ? null : data.error,
        p_ip_address: ipAddress,
        p_user_agent: userAgent,
        p_metadata: JSON.stringify({
          timestamp: Math.floor(Date.now() / 1000),
          client_info: {
            ip: ipAddress,
            user_agent: userAgent
          }
        })
      });
    } catch (logError) {
      console.warn('[ACTIVITY LOG WARNING]', logError);
      // Don't fail validation if logging fails
    }

    console.log(`[LICENSE VALIDATION] ${licenseKey}: ${data.success ? 'VALID' : 'INVALID'} (${data.error || data.message || 'N/A'})`);
    
    return data;
    
  } catch (error) {
    console.error('[VALIDATION ERROR]', error);
    return {
      success: false,
      error: 'system_error',
      message: 'เกิดข้อผิดพลาดของระบบ'
    };
  }
}
