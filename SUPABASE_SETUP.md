# Supabase setup

1. Create a Supabase project at https://supabase.com.
2. Open Project Settings -> API.
3. Copy:
   - Project URL into `VITE_SUPABASE_URL`
   - anon public / publishable key into `VITE_SUPABASE_PUBLISHABLE_KEY`
4. Create `.env.local` in the project root:

```env
VITE_SUPABASE_URL=https://your-project.supabase.co
VITE_SUPABASE_PUBLISHABLE_KEY=your-public-key
```

5. Install the client:

```bash
npm install @supabase/supabase-js
```

6. Run the SQL from `supabase/schema.sql` in Supabase SQL Editor.

7. Restart the local dev server after changing `.env.local`.

The CRM now uses `crm_app_state` as the main cloud snapshot table. The other CRM tables are also created for future reports and integrations, but the first stable sync stores the whole current CRM state in `crm_app_state`.
