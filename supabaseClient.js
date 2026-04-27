import { createClient } from "https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/+esm";

const appConfig = window.__APP_CONFIG__ || {};
const supabaseUrl = appConfig.SUPABASE_URL || appConfig.VITE_SUPABASE_URL || "";
const supabaseAnonKey = appConfig.SUPABASE_ANON_KEY || appConfig.VITE_SUPABASE_ANON_KEY || "";

if (!supabaseUrl || !supabaseAnonKey) {
  console.error("Supabase is not configured. Set SUPABASE_URL and SUPABASE_ANON_KEY in Netlify.");
}

export const supabase = createClient(supabaseUrl || "https://example.supabase.co", supabaseAnonKey || "missing-key", {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
    storageKey: "productiv-line-auth",
  },
});
