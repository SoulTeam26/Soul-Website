// ============================================================
// Soul Web - Minecraft identity relay (Vercel serverless function)
// POST { accessToken: <Microsoft OAuth access token with XboxLive.signin> }
// -> Xbox Live -> XSTS -> api.minecraftservices.com (login_with_xbox,
//    /minecraft/profile)
// -> { uuid, name, verified: true }
//
// The relay is stateless: it stores NOTHING (no tokens, no logs of them).
// It only exists because api.minecraftservices.com does not send CORS
// headers, so the browser cannot call it directly.
// XErr reference: https://wiki.vg/Microsoft_Authentication_Scheme
// ============================================================

const AAD = 'https://login.microsoftonline.com';

async function json(res) {
  const text = await res.text();
  try { return JSON.parse(text); } catch (e) { return { raw: text }; }
}

module.exports = async (req, res) => {
  // CORS (same-origin use, but echo the origin to be safe for previews)
  const origin = req.headers.origin || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Vary', 'Origin');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'POST only' });

  let body = {};
  try { body = typeof req.body === 'string' ? JSON.parse(req.body) : (req.body || {}); } catch (e) {}

  // Optional: a refresh token can be supplied so the relay can mint a fresh
  // access token itself (used when the browser session outlives the token).
  let accessToken = String(body.accessToken || '').trim();
  const refreshToken = String(body.refreshToken || '').trim();

  if (!accessToken && refreshToken) {
    // Refresh path is optional and only used if a refresh_token is passed.
    try {
      const rres = await fetch(`${AAD}/consumers/oauth2/v2.0/token`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          client_id: String(body.clientId || ''),
          grant_type: 'refresh_token',
          refresh_token: refreshToken,
          scope: 'XboxLive.signin offline_access openid profile email'
        }).toString()
      });
      const tok = await json(rres);
      if (tok && tok.access_token) accessToken = tok.access_token;
    } catch (e) {}
  }

  if (!accessToken) return res.status(400).json({ error: 'Missing accessToken' });

  try {
    // 1) Xbox Live user token (RPS ticket = "d=" + Microsoft access token)
    const xblRes = await fetch('https://user.auth.xboxlive.com/user/authenticate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        Properties: {
          AuthMethod: 'RPS',
          SiteName: 'user.auth.xboxlive.com',
          RpsTicket: 'd=' + accessToken
        },
        RelyingParty: 'http://auth.xboxlive.com',
        TokenType: 'JWT'
      })
    });
    const xbl = await json(xblRes);
    if (!xblRes.ok || !xbl.Token || !xbl.DisplayClaims || !xbl.DisplayClaims.xui || !xbl.DisplayClaims.xui[0]) {
      console.warn('[mc-auth] xbl failed', xblRes.status, JSON.stringify(xbl || {}).slice(0, 300));
      return res.status(401).json({ error: 'Xbox Live rejected the Microsoft token (status ' + xblRes.status + ')' });
    }
    const xblToken = xbl.Token;
    const uhs = xbl.DisplayClaims.xui[0].uhs;

    // 2) XSTS token (real Minecraft relying party)
    const xstsRes = await fetch('https://xsts.auth.xboxlive.com/xsts/authorize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({
        Properties: { SandboxId: 'RETAIL', UserTokens: [xblToken] },
        RelyingParty: 'rp://api.minecraftservices.com/',
        TokenType: 'JWT'
      })
    });
    const xsts = await json(xstsRes);
    if (!xstsRes.ok || !xsts.Token) {
      const xerr = (xsts && (xsts.XErr || (xsts.raw && xsts.raw))) || null;
      console.warn('[mc-auth] xsts failed', xstsRes.status, JSON.stringify(xsts || {}).slice(0, 300));
      return res.status(401).json({
        error: 'Xbox/XSTS authorization failed',
        errorCode: xerr !== null && xerr !== undefined ? String(xerr) : undefined,
        hint: 'The Microsoft account may not have Xbox/Minecraft entitlements.'
      });
    }
    const xstsToken = xsts.Token;

    // 3) Minecraft access token
    const mcRes = await fetch('https://api.minecraftservices.com/authentication/login_with_xbox', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
      body: JSON.stringify({ identityToken: 'XBL3.0 x=' + uhs + ';' + xstsToken })
    });
    const mc = await json(mcRes);
    if (!mcRes.ok || !mc.access_token) {
      console.warn('[mc-auth] minecraft login failed', mcRes.status, JSON.stringify(mc || {}).slice(0, 300));
      return res.status(401).json({ error: 'Minecraft login failed', step: 'login_with_xbox', status: mcRes.status });
    }

    // 4) Verified Minecraft profile
    const profRes = await fetch('https://api.minecraftservices.com/minecraft/profile', {
      headers: { Authorization: 'Bearer ' + mc.access_token, Accept: 'application/json' }
    });
    const prof = await json(profRes);
    if (!profRes.ok || !prof.id || !prof.name) {
      // 404 -> the Microsoft account has no Minecraft Java profile
      console.warn('[mc-auth] profile fetch failed', profRes.status);
      return res.status(profRes.status === 404 ? 404 : 401).json({
        error: profRes.status === 404
          ? 'This Microsoft account does not own Minecraft: Java Edition.'
          : 'Could not fetch the Minecraft profile.',
        errorCode: profRes.status === 404 ? '2148916233' : undefined
      });
    }

    return res.status(200).json({
      verified: true,
      uuid: String(prof.id).replace(/-/g, '').toLowerCase(),
      name: prof.name
    });
  } catch (e) {
    console.error('[mc-auth] relay error', e);
    return res.status(500).json({ error: 'Relay error: ' + (e && e.message ? e.message : String(e)) });
  }
};
