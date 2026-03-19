interface APIResponse<T> {
	data: T | null;
	error: { code: string; message: string } | null;
}

function getCSRFToken(): string | undefined {
	const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]*)/);
	return match ? decodeURIComponent(match[1]) : undefined;
}

class APIClient {
	private baseURL: string;
	private refreshing: Promise<boolean> | null = null;

	constructor(baseURL = '') {
		this.baseURL = baseURL;
	}

	private async request<T>(method: string, path: string, body?: unknown): Promise<T> {
		const headers: Record<string, string> = { 'Content-Type': 'application/json' };
		const csrf = getCSRFToken();
		if (csrf) {
			headers['X-CSRF-Token'] = csrf;
		}
		const opts: RequestInit = {
			method,
			headers,
			credentials: 'include'
		};

		if (body) {
			opts.body = JSON.stringify(body);
		}

		const res = await fetch(`${this.baseURL}${path}`, opts);

		if (res.status === 401) {
			// Attempt to refresh the session (once)
			const refreshed = await this.tryRefresh();
			if (refreshed) {
				// Retry the original request
				const retry = await fetch(`${this.baseURL}${path}`, opts);
				if (retry.status === 401) {
					window.location.href = '/login';
					throw new Error('Unauthorized');
				}
				const json: APIResponse<T> = await retry.json();
				if (json.error) {
					throw new Error(json.error.message);
				}
				return json.data as T;
			}
			window.location.href = '/login';
			throw new Error('Unauthorized');
		}

		const json: APIResponse<T> = await res.json();

		if (json.error) {
			throw new Error(json.error.message);
		}

		return json.data as T;
	}

	private async tryRefresh(): Promise<boolean> {
		// Deduplicate concurrent refresh attempts
		if (this.refreshing) {
			return this.refreshing;
		}
		this.refreshing = (async () => {
			try {
				const headers: Record<string, string> = {};
				const csrf = getCSRFToken();
				if (csrf) {
					headers['X-CSRF-Token'] = csrf;
				}
				const res = await fetch(`${this.baseURL}/auth/refresh`, {
					method: 'POST',
					headers,
					credentials: 'include'
				});
				return res.ok;
			} catch {
				return false;
			} finally {
				this.refreshing = null;
			}
		})();
		return this.refreshing;
	}

	// Auth
	async me() {
		return this.request<{ id: string; email: string; name: string; role: string }>('GET', '/auth/me');
	}

	async logout() {
		return this.request<void>('POST', '/auth/logout');
	}

	// Server
	async getServer() {
		return this.request<ServerConfig>('GET', '/api/v1/server');
	}

	async updateServer(data: Partial<ServerConfig>) {
		return this.request<ServerConfig>('PUT', '/api/v1/server', data);
	}

	async applyServer() {
		return this.request<{ message: string }>('POST', '/api/v1/server/apply');
	}

	// Peers
	async listPeers() {
		return this.request<Peer[]>('GET', '/api/v1/peers');
	}

	async getPeer(id: string) {
		return this.request<Peer>('GET', `/api/v1/peers/${id}`);
	}

	async createPeer(data: { name: string; allowed_ips?: string; dns?: string; public_key?: string }) {
		return this.request<CreatePeerResponse>('POST', '/api/v1/peers', data);
	}

	async updatePeer(id: string, data: Partial<Peer>) {
		return this.request<Peer>('PUT', `/api/v1/peers/${id}`, data);
	}

	async deletePeer(id: string) {
		return this.request<void>('DELETE', `/api/v1/peers/${id}`);
	}

	async togglePeer(id: string) {
		return this.request<Peer>('PATCH', `/api/v1/peers/${id}/toggle`);
	}

	async regeneratePeer(id: string, publicKey: string) {
		return this.request<CreatePeerResponse>('POST', `/api/v1/peers/${id}/regenerate`, { public_key: publicKey });
	}

	getConfigURL(id: string) {
		return `/api/v1/peers/${id}/config`;
	}

	getQRCodeURL(id: string) {
		return `/api/v1/peers/${id}/qrcode`;
	}

	// Stats
	async getStats() {
		return this.request<PeerStats[]>('GET', '/api/v1/stats');
	}

	// Users
	async listUsers() {
		return this.request<User[]>('GET', '/api/v1/users');
	}

	async getUser(id: string) {
		return this.request<User>('GET', `/api/v1/users/${id}`);
	}

	async createUser(data: { username: string; password: string; name?: string; role?: string }) {
		return this.request<User>('POST', '/api/v1/users', data);
	}

	async updateUser(id: string, data: { username?: string; name?: string; role?: string }) {
		return this.request<User>('PUT', `/api/v1/users/${id}`, data);
	}

	async deleteUser(id: string) {
		return this.request<void>('DELETE', `/api/v1/users/${id}`);
	}

	async resetPassword(id: string, password: string) {
		return this.request<{ message: string }>('POST', `/api/v1/users/${id}/reset-password`, { password });
	}

	async changePassword(currentPassword: string, newPassword: string) {
		return this.request<{ message: string }>('POST', '/api/v1/me/password', {
			current_password: currentPassword,
			new_password: newPassword
		});
	}

	// API Tokens
	async listTokens() {
		return this.request<APIToken[]>('GET', '/api/v1/me/tokens');
	}

	async createToken(name: string) {
		return this.request<APITokenCreateResponse>('POST', '/api/v1/me/tokens', { name });
	}

	async deleteToken(id: string) {
		return this.request<void>('DELETE', `/api/v1/me/tokens/${id}`);
	}

	// Groups
	async listGroups() {
		return this.request<Group[]>('GET', '/api/v1/groups');
	}

	async getGroup(id: string) {
		return this.request<Group>('GET', `/api/v1/groups/${id}`);
	}

	async createGroup(data: { name: string }) {
		return this.request<Group>('POST', '/api/v1/groups', data);
	}

	async updateGroup(id: string, data: { name: string }) {
		return this.request<Group>('PUT', `/api/v1/groups/${id}`, data);
	}

	async deleteGroup(id: string) {
		return this.request<void>('DELETE', `/api/v1/groups/${id}`);
	}

	async getGroupMembers(id: string) {
		return this.request<User[]>('GET', `/api/v1/groups/${id}/members`);
	}

	async getUserGroups(userId: string) {
		return this.request<Group[]>('GET', `/api/v1/users/${userId}/groups`);
	}

	async setUserGroups(userId: string, groupIds: string[]) {
		return this.request<Group[]>('PUT', `/api/v1/users/${userId}/groups`, { group_ids: groupIds });
	}

	// ACL Rules
	async listACLRules() {
		return this.request<ACLRule[]>('GET', '/api/v1/acls');
	}

	async getACLRule(id: string) {
		return this.request<ACLRule>('GET', `/api/v1/acls/${id}`);
	}

	async createACLRule(data: Partial<ACLRule>) {
		return this.request<ACLRule>('POST', '/api/v1/acls', data);
	}

	async updateACLRule(id: string, data: Partial<ACLRule>) {
		return this.request<ACLRule>('PUT', `/api/v1/acls/${id}`, data);
	}

	async deleteACLRule(id: string) {
		return this.request<void>('DELETE', `/api/v1/acls/${id}`);
	}

	async getEffectiveACLRules(userId: string) {
		return this.request<ACLRule[]>('GET', `/api/v1/acls/effective/${userId}`);
	}

	async reloadACL() {
		return this.request<{ message: string }>('POST', '/api/v1/acls/reload');
	}

	// Tunnels
	async listTunnels() {
		return this.request<TunnelWithStatus[]>('GET', '/api/v1/tunnels');
	}

	async getTunnel(id: string) {
		return this.request<Tunnel>('GET', `/api/v1/tunnels/${id}`);
	}

	async createTunnel(data: CreateTunnelRequest) {
		return this.request<CreateTunnelResponse>('POST', '/api/v1/tunnels', data);
	}

	async updateTunnel(id: string, data: Partial<Tunnel>) {
		return this.request<Tunnel>('PUT', `/api/v1/tunnels/${id}`, data);
	}

	async deleteTunnel(id: string) {
		return this.request<void>('DELETE', `/api/v1/tunnels/${id}`);
	}

	async toggleTunnel(id: string) {
		return this.request<Tunnel>('PATCH', `/api/v1/tunnels/${id}/toggle`);
	}

	async getTunnelStatus(id: string) {
		return this.request<TunnelStatus>('GET', `/api/v1/tunnels/${id}/status`);
	}

	getTunnelRemoteConfigURL(id: string) {
		return `/api/v1/tunnels/${id}/config`;
	}

	// MFA Management (authenticated)
	async getMFAStatus() {
		return this.request<MFAStatus>('GET', '/api/v1/me/mfa');
	}

	async webauthnRegisterBegin() {
		return this.request<{ challenge_id: string; options: PublicKeyCredentialCreationOptionsJSON }>('POST', '/api/v1/me/mfa/webauthn/register/begin');
	}

	async webauthnRegisterFinish(challengeId: string, name: string, response: unknown) {
		return this.request<{ id: string; name: string }>('POST', '/api/v1/me/mfa/webauthn/register/finish', {
			challenge_id: challengeId,
			name,
			response
		});
	}

	async deleteWebAuthnCredential(id: string) {
		return this.request<void>('DELETE', `/api/v1/me/mfa/webauthn/${id}`);
	}

	async totpEnroll() {
		return this.request<{ secret: string; qr_uri: string }>('POST', '/api/v1/me/mfa/totp/enroll');
	}

	async totpVerify(code: string) {
		return this.request<{ message: string }>('POST', '/api/v1/me/mfa/totp/verify', { code });
	}

	async totpDelete() {
		return this.request<void>('DELETE', '/api/v1/me/mfa/totp');
	}
}

export interface ServerConfig {
	id: string;
	public_key: string;
	listen_port: number;
	address: string;
	dns: string;
	mtu: number;
	post_up: string;
	post_down: string;
	endpoint: string;
	default_allowed_ips: string;
	default_dns: string;
	tunnel_subnet: string;
}

export interface Peer {
	id: string;
	name: string;
	public_key: string;
	allowed_ips: string;
	address: string;
	dns: string;
	persistent_keepalive: number;
	enabled: boolean;
	created_by: string;
	created_by_name?: string;
	created_at: string;
	updated_at: string;
}

export interface User {
	id: string;
	username: string;
	name: string;
	role: string;
	created_at: string;
}

export interface APIToken {
	id: string;
	user_id: string;
	name: string;
	token_prefix: string;
	last_used: string | null;
	expires_at: string | null;
	created_at: string;
}

export interface APITokenCreateResponse {
	id: string;
	name: string;
	token: string;
	token_prefix: string;
	created_at: string;
}

export interface Group {
	id: string;
	name: string;
	source: string;
	created_at: string;
}

export interface ACLRule {
	id: string;
	name: string;
	description: string;
	priority: number;
	action: string;
	protocol: string;
	dst_cidr: string;
	dst_ports: string;
	group_id: string | null;
	user_id: string | null;
	enabled: boolean;
	created_at: string;
	updated_at: string;
}

export interface CreatePeerResponse extends Peer {
	preshared_key?: string;
}

export interface PeerStats {
	public_key: string;
	endpoint: string;
	last_handshake: string;
	transfer_rx: number;
	transfer_tx: number;
	connected: boolean;
}

export interface Tunnel {
	id: string;
	name: string;
	description: string;
	public_key: string;
	address: string;
	listen_port: number;
	dns: string;
	mtu: number;
	peer_public_key: string;
	peer_endpoint: string;
	peer_allowed_ips: string;
	persistent_keepalive: number;
	enabled: boolean;
	created_at: string;
	updated_at: string;
}

export interface TunnelStatus {
	tunnel_id: string;
	connected: boolean;
	last_handshake?: string;
	transfer_rx: number;
	transfer_tx: number;
	endpoint?: string;
}

export interface TunnelWithStatus extends Tunnel {
	status: TunnelStatus | null;
}

export interface CreateTunnelRequest {
	name: string;
	description?: string;
	private_key?: string;
	public_key?: string;
	address?: string;
	listen_port?: number;
	dns?: string;
	mtu?: number;
	peer_public_key?: string;
	peer_endpoint?: string;
	peer_allowed_ips?: string;
	persistent_keepalive?: number;
	preshared_key?: string;
}

export interface CreateTunnelResponse extends Tunnel {
	preshared_key?: string;
}

// MFA Types
export interface MFAStatus {
	mfa_enabled: boolean;
	webauthn_credentials: WebAuthnCredentialInfo[];
	totp_enrolled: boolean;
}

export interface WebAuthnCredentialInfo {
	id: string;
	name: string;
	created_at: string;
	last_used_at: string | null;
}

export interface LoginResponse {
	user?: { id: string; username: string; name: string; role: string };
	mfa_required?: boolean;
	mfa_token?: string;
	mfa_methods?: string[];
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
export type PublicKeyCredentialCreationOptionsJSON = any;

export const api = new APIClient();
