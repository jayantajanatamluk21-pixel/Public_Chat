# BYTECHAT — runnable messaging MVP

BYTECHAT is a self-hosted, browser-first messaging starter with a responsive PWA-style interface. It can be installed from supported browsers on Android and desktop; the same web client can be wrapped for Windows/Android later. This is a working MVP, **not a production-ready WhatsApp replacement**.

## Included

- Username/password accounts (bcrypt password hashes; JWT sessions)
- Direct messages and groups
- Real-time text messaging with Socket.IO
- Image/file upload and sharing (default limit 15 MB)
- Profiles and 24-hour text statuses
- One-to-one WebRTC voice/video call signaling
- SQLite persistence
- Responsive dark UI

## Important security limitations

- **End-to-end encryption is NOT implemented in this MVP.** The UI can display an encrypted-message marker, but current messages are plaintext JSON on the server. Do not use this for sensitive conversations. Production E2EE requires a reviewed protocol and device/key lifecycle (for example, a maintained Signal Protocol implementation), authenticated key exchange, identity verification, encrypted attachments, multi-device handling, and security review. Do not invent your own cryptographic protocol.
- Uploaded files are stored on the server and are **not encrypted end-to-end**. Files are currently served as static files; production should use authenticated object storage, access checks, malware scanning, quotas, and short-lived URLs.
- Statuses are visible to all signed-in users in this starter, not a privacy-selected audience.
- Calls use WebRTC with a public STUN server only. Some NAT/firewall networks require a TURN server. Calls are one-to-one only; group calling is not implemented.
- The default JWT secret is for local development only. Set a strong secret and HTTPS before any shared or public deployment.
- Rate limiting is currently applied to login/register only. Add broader abuse prevention, email/phone verification if required, audit logs, backups, monitoring, and account recovery before production.
- The default Helmet CSP is relaxed for this inline-script starter. Tighten CSP and review dependencies before deployment.

## Requirements

- Node.js 20 or newer
- npm
- Internet connection for `npm install` (runtime messaging is hosted by your server)

## Windows quick start

1. Extract the ZIP to a folder such as `C:\\BYTECHAT`.
2. Install Node.js LTS from https://nodejs.org/ if it is not installed.
3. Open Command Prompt in the extracted `BYTECHAT` folder.
4. Install packages:

   ```bat
   npm install
   ```

5. Create your environment file:

   ```bat
   copy .env.example .env
   ```

6. Edit `.env` and replace `JWT_SECRET` with a long random secret. Example generation command in PowerShell:

   ```powershell
   [Convert]::ToBase64String([Security.Cryptography.RandomNumberGenerator]::GetBytes(48))
   ```

   Paste the result after `JWT_SECRET=` in `.env`.

7. Start the server:

   ```bat
   npm start
   ```

8. Open http://localhost:3000 and create an account. Open a second browser or another device to create another account and test messaging.

## Testing on a phone or another PC on the same Wi-Fi

- Find the host PC's LAN IP with `ipconfig`.
- Open `http://YOUR-PC-LAN-IP:3000` on the other device.
- Allow Node.js through Windows Firewall for a private network if prompted.
- This LAN test is **not encrypted transport**. Do not enter real passwords or sensitive content over untrusted networks.
- Browser camera/microphone permissions generally require HTTPS or localhost. For remote use, deploy behind HTTPS and configure a TURN server.

## Storage

- SQLite database: `data/bytechat.sqlite`
- Uploads: `uploads/`
- Back up both directories while the server is stopped.

## API overview

- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/me`, `PATCH /api/me`
- `GET /api/users?q=...`
- `GET /api/rooms`
- `POST /api/rooms/dm`
- `POST /api/rooms/group`
- `GET /api/rooms/:id/messages`
- `POST /api/upload`
- `GET /api/status`, `POST /api/status`
- Socket.IO events: `message:send`, `message:new`, `rooms:changed`, `call:signal`

## Roadmap before production

1. Add reviewed end-to-end encryption for messages and attachments.
2. Enforce private status audiences and message/report/block controls.
3. Move uploads to private object storage and authorize every download.
4. Add HTTPS reverse proxy, TURN, email/phone verification, recovery, monitoring, backups, and deployment secrets.
5. Add mobile push notifications, multi-device key management, group call SFU, and native Android/Windows packaging.
6. Add automated tests and independent security review.

## Production deployment note

Use a supported Node.js LTS release, HTTPS reverse proxy, managed database/object storage, strong secrets, backups, monitoring, dependency scanning, and a TURN service. Never expose the development server directly to the public internet.
