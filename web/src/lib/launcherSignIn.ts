import { supabase } from './supabase'

export async function acceptLauncherSignIn() {
  const pendingKey = 'cremis-launcher-signin';
  const fragment = new URLSearchParams(window.location.hash.slice(1));
  const ticket = fragment.get('launch');
  const saved = sessionStorage.getItem(pendingKey);
  if (!ticket && !saved) return true;

  let expectedEmail;
  if (ticket) {
    sessionStorage.removeItem(pendingKey);
    window.history.replaceState(null, '', window.location.pathname);
    const response = await fetch('https://zcfgyobgjgluqgxzwfqc.supabase.co/rest/v1/rpc/consume_portal_launch', {
      method: 'POST', headers: { apikey: 'sb_publishable_y8bDYgfR7g1bAX9uxNhzWg_mLUhnRf_', 'Content-Type': 'application/json' },
      body: JSON.stringify({ launch_ticket: ticket }), cache: 'no-store',
    });
    const rows = response.ok ? await response.json() : [];
    if (rows[0]?.app !== 'Security Console' || !rows[0]?.email) throw new Error('This app link has expired or access has changed.');
    expectedEmail = rows[0].email.toLowerCase();
  } else {
    sessionStorage.removeItem(pendingKey);
    const pending = JSON.parse(saved!);
    if (Date.now() >= pending.expires || fragment.has('error') || new URLSearchParams(location.search).has('error'))
      throw new Error('Microsoft sign-in expired or was cancelled.');
    expectedEmail = pending.email;
  }

  if (!supabase) throw new Error('Console sign-in is unavailable.');
  const { data, error } = await supabase.auth.getSession();
  if (error) throw error;
  if (data.session?.user.email?.toLowerCase() === expectedEmail) return true;
  if (!ticket) throw new Error('Microsoft did not return the assigned staff account.');

  sessionStorage.setItem(pendingKey, JSON.stringify({ email: expectedEmail, expires: Date.now() + 600000 }));
  const result = await supabase.auth.signInWithOAuth({
    provider: 'azure', options: { scopes: 'openid profile email offline_access User.Read User.Read.All Files.ReadWrite.All', redirectTo: window.location.origin, queryParams: { login_hint: expectedEmail } },
  });
  if (result.error) { sessionStorage.removeItem(pendingKey); throw result.error; }
  return false;
}
