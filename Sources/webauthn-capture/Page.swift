import Foundation

extension Capture {

    /// The page the browser runs the ceremony from.
    ///
    /// The only JavaScript in this repository, and it stays here rather than in a resource file
    /// so the tool is one `swift run` with nothing to locate at runtime.
    ///
    /// `localhost` is a secure context by definition, which is why this needs no TLS.
    static let page = """
        <!doctype html><meta charset=utf-8><title>WebAuthn capture</title>
        <style>
         :root { color-scheme: light dark }
         body{font:16px/1.6 -apple-system,system-ui,sans-serif;max-width:44rem;margin:4rem auto;padding:0 1.5rem}
         button{font:inherit;padding:.7rem 1.4rem;margin-right:.75rem;border:1px solid currentColor;
                background:transparent;color:inherit;border-radius:.4rem;cursor:pointer}
         button:hover:not(:disabled){background:currentColor}
         button:hover:not(:disabled) span{mix-blend-mode:difference;color:#fff}
         button:disabled{opacity:.35;cursor:not-allowed}
         pre{background:color-mix(in srgb, currentColor 8%, transparent);padding:1rem;
             border-radius:.4rem;overflow-x:auto;font-size:13px;white-space:pre-wrap}
         small{opacity:.7}
        </style>
        <h1>Capture a ceremony</h1>
        <p>Register, then authenticate. Each step asks for Touch ID, and each is verified by
        SwiftWebAuthn before anything is written.</p>
        <p><button id=reg><span>1 · Register</span></button><button id=auth disabled><span>2 · Authenticate</span></button></p>
        <pre id=log>ready</pre>
        <p><small>Nothing secret is captured: an attestation object carries a public key, and the
        private half never leaves the Secure Enclave. The passkey itself can be deleted afterwards
        without invalidating anything — verification is arithmetic over the recorded bytes.</small></p>
        <script>
        const log = document.getElementById('log');
        const say = (m) => { log.textContent = m; };
        const dec = (s) => Uint8Array.from(atob(s.replace(/-/g,'+').replace(/_/g,'/')), c => c.charCodeAt(0));
        const enc = (b) => btoa(String.fromCharCode(...new Uint8Array(b)))
                             .replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'');

        async function post(path, body) {
          const r = await fetch(path, {method:'POST', body: JSON.stringify(body)});
          return r.json();
        }

        document.getElementById('reg').onclick = async () => {
          try {
            const o = await (await fetch('/register/options')).json();
            o.challenge = dec(o.challenge);
            o.user.id = dec(o.user.id);
            o.excludeCredentials = (o.excludeCredentials || []).map(c => ({...c, id: dec(c.id)}));
            say('touch the sensor…');
            const c = await navigator.credentials.create({publicKey: o});
            const r = await post('/register/result', {
              credentialID: enc(c.rawId),
              clientDataJSON: enc(c.response.clientDataJSON),
              attestationObject: enc(c.response.attestationObject),
            });
            say('REGISTERED — verified by SwiftWebAuthn\\n\\n' + JSON.stringify(r, null, 2));
            document.getElementById('auth').disabled = false;
          } catch (e) { say('FAILED: ' + e); }
        };

        document.getElementById('auth').onclick = async () => {
          try {
            const o = await (await fetch('/auth/options')).json();
            o.challenge = dec(o.challenge);
            o.allowCredentials = (o.allowCredentials || []).map(c => ({...c, id: dec(c.id)}));
            say('touch the sensor…');
            const c = await navigator.credentials.get({publicKey: o});
            const r = await post('/auth/result', {
              credentialID: enc(c.rawId),
              clientDataJSON: enc(c.response.clientDataJSON),
              authenticatorData: enc(c.response.authenticatorData),
              signature: enc(c.response.signature),
              userHandle: c.response.userHandle ? enc(c.response.userHandle) : null,
            });
            say('AUTHENTICATED — verified by SwiftWebAuthn\\n\\n' + JSON.stringify(r, null, 2));
          } catch (e) { say('FAILED: ' + e); }
        };
        </script>
        """
}
