import fs from "node:fs";
import path from "node:path";

const supabaseUrl = process.env.SUPABASE_URL || process.env.VITE_SUPABASE_URL || "";
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY || process.env.VITE_SUPABASE_ANON_KEY || "";

if (!supabaseUrl || !supabaseAnonKey) {
  throw new Error("SUPABASE_URL/SUPABASE_ANON_KEY or VITE_SUPABASE_URL/VITE_SUPABASE_ANON_KEY must be set for build.");
}

const out = `window.__APP_CONFIG__ = {
  SUPABASE_URL: ${JSON.stringify(supabaseUrl)},
  SUPABASE_ANON_KEY: ${JSON.stringify(supabaseAnonKey)},
  VITE_SUPABASE_URL: ${JSON.stringify(supabaseUrl)},
  VITE_SUPABASE_ANON_KEY: ${JSON.stringify(supabaseAnonKey)}
};
`;

fs.writeFileSync(path.join(process.cwd(), "env.js"), out, "utf8");
